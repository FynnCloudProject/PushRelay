import APNSCore
import Foundation
import Vapor

public struct PushDeliveryOutcome: Sendable, Equatable {
    public let status: HTTPResponseStatus
    public let response: PushResponse

    public init(status: HTTPResponseStatus, response: PushResponse) {
        self.status = status
        self.response = response
    }
}

public final class APNSService: Sendable {
    public static let maxAlertPayloadBytes = 4_096
    public static let maxVoIPPayloadBytes = 5_120
    public static let maxFileProviderPayloadBytes = 4_096
    public static let defaultFileProviderContainerIdentifier = "NSFileProviderWorkingSetContainerItemIdentifier"
    public static let defaultVoIPTTLSeconds = 45
    public static let maxVoIPTTLSeconds = 300
    public static let maxAlertTTLSeconds = 30 * 24 * 3_600

    private static let unregisteredReasons: Set<APNSError.ErrorReason> = [
        .unregistered,
        .badDeviceToken,
        .deviceTokenNotForTopic,
        .expiredToken,
    ]

    private static let relayConfigReasons: Set<APNSError.ErrorReason> = [
        .expiredProviderToken,
        .invalidProviderToken,
        .missingProviderToken,
        .topicDisallowed,
        .badCertificate,
        .badCertificateEnvironment,
        .badEnvironmentKeyIdInToken,
        .unrelatedKeyIdInToken,
        .topicMismatch,
        .forbidden,
    ]

    public let config: APNSConfig
    private let productionClient: any APNSClientProtocol
    private let sandboxClient: (any APNSClientProtocol)?
    private let now: @Sendable () -> Date

    public init(
        config: APNSConfig,
        productionClient: any APNSClientProtocol,
        sandboxClient: (any APNSClientProtocol)? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.config = config
        self.productionClient = productionClient
        self.sandboxClient = sandboxClient
        self.now = now
    }

    public func send(_ req: PushRequest) async -> PushDeliveryOutcome {
        do {
            return try await dispatchValidated(req)
        } catch let err as ValidationFailure {
            return PushDeliveryOutcome(status: err.status, response: PushResponse(delivered: false, reason: err.reason))
        } catch let err as APNSError {
            return Self.mapError(err)
        } catch {
            return PushDeliveryOutcome(status: .badGateway, response: PushResponse(delivered: false, reason: "apns_transport_error"))
        }
    }

    private struct ValidationFailure: Error {
        let status: HTTPResponseStatus
        let reason: String
    }

    private struct EncryptedPayload: Encodable, Sendable {
        let k: String
        let c: String
    }

    private struct FileProviderPayload: Encodable, Sendable {
        let containerIdentifier: String
        let domain: String?

        enum CodingKeys: String, CodingKey {
            case containerIdentifier = "container-identifier"
            case domain
        }
    }

    private func dispatchValidated(_ req: PushRequest) async throws -> PushDeliveryOutcome {
        let env = req.environment ?? .production
        let client: any APNSClientProtocol
        switch env {
        case .production:
            client = productionClient
        case .sandbox:
            guard config.allowSandbox, let sandboxClient else {
                throw ValidationFailure(status: .forbidden, reason: "sandbox_disabled")
            }
            client = sandboxClient
        }

        let target = req.target.trimmingCharacters(in: .whitespacesAndNewlines)
        let isVoIP = (req.transport == .apnsVoip)
        let isFileProvider = (req.transport == .apnsFileProvider)
        let effectiveKind: PushKind

        if isVoIP {
            guard config.allowedVoIPTopics.contains(target) else {
                throw ValidationFailure(status: .forbidden, reason: "topic_not_allowed")
            }
            guard (req.kind ?? .voip) == .voip else {
                throw ValidationFailure(status: .badRequest, reason: "apns_voip_requires_voip_kind")
            }
            effectiveKind = .voip
        } else if isFileProvider {
            guard config.allowedFileProviderTopics.contains(target) else {
                throw ValidationFailure(status: .forbidden, reason: "topic_not_allowed")
            }
            guard (req.kind ?? .fileprovider) == .fileprovider else {
                throw ValidationFailure(status: .badRequest, reason: "apns_fileprovider_requires_fileprovider_kind")
            }
            effectiveKind = .fileprovider
        } else {
            guard config.allowedTopics.contains(target) else {
                throw ValidationFailure(status: .forbidden, reason: "topic_not_allowed")
            }
            let requestedKind = req.kind ?? .alert
            guard requestedKind == .alert || requestedKind == .background else {
                throw ValidationFailure(status: .badRequest, reason: "apns_requires_alert_or_background_kind")
            }
            effectiveKind = requestedKind
        }

        let token = req.token.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard Self.isValidHexToken(token) else {
            throw ValidationFailure(status: .badRequest, reason: "invalid_apns_token")
        }

        let currentUnix = Int(now().timeIntervalSince1970)
        let expiration: APNSNotificationExpiration
        if isVoIP {
            let ttl = max(0, min(req.ttlSeconds ?? Self.defaultVoIPTTLSeconds, Self.maxVoIPTTLSeconds))
            expiration = ttl == 0 ? .immediately : .timeIntervalSince1970InSeconds(currentUnix + ttl)
        } else if let requestedTTL = req.ttlSeconds {
            let ttl = max(0, min(requestedTTL, Self.maxAlertTTLSeconds))
            expiration = ttl == 0 ? .immediately : .timeIntervalSince1970InSeconds(currentUnix + ttl)
        } else {
            expiration = .none
        }

        if effectiveKind == .fileprovider {
            let rawContainer = req.containerIdentifier?.trimmingCharacters(in: .whitespacesAndNewlines)
            let containerIdentifier = (rawContainer?.isEmpty == false)
                ? rawContainer!
                : Self.defaultFileProviderContainerIdentifier
            guard Self.isValidFileProviderIdentifier(containerIdentifier) else {
                throw ValidationFailure(status: .badRequest, reason: "invalid_container_identifier")
            }

            var validatedDomain: String?
            if let rawDomain = req.domain?.trimmingCharacters(in: .whitespacesAndNewlines), !rawDomain.isEmpty {
                guard Self.isValidFileProviderIdentifier(rawDomain) else {
                    throw ValidationFailure(status: .badRequest, reason: "invalid_fileprovider_domain")
                }
                validatedDomain = rawDomain
            }

            let notification = APNSFileProviderNotification(
                expiration: expiration,
                topic: target,
                payload: FileProviderPayload(
                    containerIdentifier: containerIdentifier,
                    domain: validatedDomain
                )
            )
            try Self.validatePayloadSize(notification, limit: Self.maxFileProviderPayloadBytes)
            let response = try await client.sendFileProviderNotification(notification, deviceToken: token)

            return PushDeliveryOutcome(
                status: .ok,
                response: PushResponse(
                    delivered: true,
                    unregistered: false,
                    apnsId: response.apnsID?.uuidString.lowercased()
                )
            )
        }

        let keyId = req.keyId?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard Self.isValidKeyID(keyId) else {
            throw ValidationFailure(status: .badRequest, reason: "invalid_key_id")
        }

        let ciphertext = req.ciphertext?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !ciphertext.isEmpty, Data(base64Encoded: ciphertext) != nil else {
            throw ValidationFailure(status: .badRequest, reason: "invalid_ciphertext")
        }

        var validatedCollapseId: String?
        if let rawCollapse = req.collapseId?.trimmingCharacters(in: .whitespacesAndNewlines), !rawCollapse.isEmpty {
            guard Self.isValidCollapseID(rawCollapse) else {
                throw ValidationFailure(status: .badRequest, reason: "invalid_collapse_id")
            }
            if !isVoIP {
                validatedCollapseId = rawCollapse
            }
        }

        let urgency = req.urgency ?? (isVoIP ? .call : .normal)
        let payload = EncryptedPayload(k: keyId, c: ciphertext)

        let response: APNSResponse
        switch effectiveKind {
        case .voip:
            let notification = APNSVoIPNotification(
                expiration: expiration,
                priority: .immediately,
                topic: target,
                payload: payload
            )
            try Self.validatePayloadSize(notification, limit: Self.maxVoIPPayloadBytes)
            response = try await client.sendVoIPNotification(notification, deviceToken: token)

        case .alert:
            let level: APNSAlertNotificationInterruptionLevel = switch urgency {
            case .call, .high: .timeSensitive
            case .low: .passive
            case .normal: .active
            }
            var notification = APNSAlertNotification(
                alert: APNSAlertNotificationContent(body: .raw("New notification")),
                expiration: expiration,
                priority: urgency == .low ? .consideringDevicePower : .immediately,
                topic: target,
                payload: payload,
                mutableContent: 1,
                interruptionLevel: level
            )
            notification.collapseID = validatedCollapseId
            try Self.validatePayloadSize(notification, limit: Self.maxAlertPayloadBytes)
            response = try await client.sendAlertNotification(notification, deviceToken: token)

        case .background:
            let notification = APNSBackgroundNotification(
                expiration: expiration,
                topic: target,
                payload: payload
            )
            try Self.validatePayloadSize(notification, limit: Self.maxAlertPayloadBytes)
            let apnsRequest = APNSRequest(
                message: notification,
                deviceToken: token,
                pushType: .background,
                expiration: notification.expiration,
                priority: .consideringDevicePower,
                apnsID: nil,
                topic: notification.topic,
                collapseID: validatedCollapseId
            )
            response = try await client.send(apnsRequest)

        case .fileprovider:
            preconditionFailure("Handled above")
        }

        return PushDeliveryOutcome(
            status: .ok,
            response: PushResponse(
                delivered: true,
                unregistered: false,
                apnsId: response.apnsID?.uuidString.lowercased()
            )
        )
    }

    private static func validatePayloadSize<M: APNSMessage>(_ message: M, limit: Int) throws {
        let encoded = try JSONEncoder().encode(message)
        guard encoded.count <= limit else {
            throw ValidationFailure(status: .payloadTooLarge, reason: "payload_too_large")
        }
    }

    private static func mapError(_ error: APNSError) -> PushDeliveryOutcome {
        let apnsId = error.apnsID?.uuidString.lowercased()
        let reason = error.reason?.reason ?? "apns_http_\(error.responseStatus)"

        if error.responseStatus == 410 || (error.responseStatus == 400 && error.reason.map(unregisteredReasons.contains) == true) {
            return PushDeliveryOutcome(
                status: .gone,
                response: PushResponse(delivered: false, unregistered: true, apnsId: apnsId, reason: reason)
            )
        }

        if error.responseStatus == 413 || error.reason == .payloadTooLarge {
            return PushDeliveryOutcome(
                status: .payloadTooLarge,
                response: PushResponse(delivered: false, apnsId: apnsId, reason: reason)
            )
        }

        if error.responseStatus == 429 || error.reason == .tooManyRequests {
            return PushDeliveryOutcome(
                status: .tooManyRequests,
                response: PushResponse(delivered: false, apnsId: apnsId, reason: reason)
            )
        }

        if error.responseStatus == 403
            || error.responseStatus == 405
            || error.reason.map(relayConfigReasons.contains) == true
            || error.reason?.reason == "BadEnvironmentKeyInToken"
        {
            return PushDeliveryOutcome(
                status: .badGateway,
                response: PushResponse(delivered: false, apnsId: apnsId, reason: reason)
            )
        }

        if error.responseStatus == 400 {
            return PushDeliveryOutcome(
                status: .badRequest,
                response: PushResponse(delivered: false, apnsId: apnsId, reason: reason)
            )
        }

        return PushDeliveryOutcome(
            status: error.responseStatus == 503 ? .serviceUnavailable : .badGateway,
            response: PushResponse(delivered: false, apnsId: apnsId, reason: reason)
        )
    }

    static func isValidHexToken(_ token: String) -> Bool {
        let count = token.utf8.count
        guard (64 ... 256).contains(count), count % 2 == 0 else { return false }
        return token.unicodeScalars.allSatisfy { scalar in
            switch scalar {
            case "0" ... "9", "a" ... "f", "A" ... "F": return true
            default: return false
            }
        }
    }

    static func isValidKeyID(_ keyId: String) -> Bool {
        guard (1 ... 64).contains(keyId.utf8.count) else { return false }
        return keyId.unicodeScalars.allSatisfy { scalar in
            switch scalar {
            case "0" ... "9", "a" ... "z", "A" ... "Z", "-", "_", ".": return true
            default: return false
            }
        }
    }

    static func isValidCollapseID(_ id: String) -> Bool {
        guard (1 ... 64).contains(id.utf8.count) else { return false }
        return id.unicodeScalars.allSatisfy { scalar in
            switch scalar {
            case "0" ... "9", "a" ... "z", "A" ... "Z", "-", "_", ".", ":": return true
            default: return false
            }
        }
    }

    static func isValidFileProviderIdentifier(_ value: String) -> Bool {
        guard (1 ... 256).contains(value.utf8.count) else { return false }
        return value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
            && value.rangeOfCharacter(from: .controlCharacters) == nil
    }
}
