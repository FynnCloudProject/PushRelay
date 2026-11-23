import Foundation
import Vapor

public enum PushTransport: String, Codable, Sendable {
    case apns = "apns"
    case apnsVoip = "apns-voip"
    case apnsFileProvider = "apns-fileprovider"
    case fcm = "fcm"
}

public enum PushEnvironment: String, Codable, Sendable {
    case production
    case sandbox
}

public enum PushKind: String, Codable, Sendable {
    case alert
    case background
    case voip
    case fileprovider
}

public enum PushUrgency: String, Codable, Sendable {
    case low
    case normal
    case high
    case call
}

public struct PushRequest: Content, Sendable {
    public var transport: PushTransport
    public var environment: PushEnvironment?
    public var target: String
    public var token: String
    public var kind: PushKind?
    public var urgency: PushUrgency?
    public var ttlSeconds: Int?
    public var collapseId: String?
    public var keyId: String?
    public var ciphertext: String?
    public var containerIdentifier: String?
    public var domain: String?

    public init(
        transport: PushTransport,
        environment: PushEnvironment? = .production,
        target: String,
        token: String,
        kind: PushKind? = nil,
        urgency: PushUrgency? = nil,
        ttlSeconds: Int? = nil,
        collapseId: String? = nil,
        keyId: String? = nil,
        ciphertext: String? = nil,
        containerIdentifier: String? = nil,
        domain: String? = nil
    ) {
        self.transport = transport
        self.environment = environment
        self.target = target
        self.token = token
        self.kind = kind
        self.urgency = urgency
        self.ttlSeconds = ttlSeconds
        self.collapseId = collapseId
        self.keyId = keyId
        self.ciphertext = ciphertext
        self.containerIdentifier = containerIdentifier
        self.domain = domain
    }
}

public struct PushResponse: Content, Sendable, Equatable {
    public let delivered: Bool
    public let unregistered: Bool
    public let apnsId: String?
    public let reason: String?

    public init(delivered: Bool, unregistered: Bool = false, apnsId: String? = nil, reason: String? = nil) {
        self.delivered = delivered
        self.unregistered = unregistered
        self.apnsId = apnsId
        self.reason = reason
    }
}

public struct PushBatchRequest: Content, Sendable {
    public var messages: [PushRequest]

    public init(messages: [PushRequest]) {
        self.messages = messages
    }
}

public struct PushBatchItemResponse: Content, Sendable, Equatable {
    public let index: Int
    public let status: UInt
    public let delivered: Bool
    public let unregistered: Bool
    public let apnsId: String?
    public let reason: String?

    public init(
        index: Int,
        status: UInt,
        delivered: Bool,
        unregistered: Bool,
        apnsId: String? = nil,
        reason: String? = nil
    ) {
        self.index = index
        self.status = status
        self.delivered = delivered
        self.unregistered = unregistered
        self.apnsId = apnsId
        self.reason = reason
    }
}

public struct PushBatchResponse: Content, Sendable, Equatable {
    public let results: [PushBatchItemResponse]

    public init(results: [PushBatchItemResponse]) {
        self.results = results
    }
}

public struct RelayTransportsStatus: Content, Sendable, Equatable {
    public let apns: Bool
    public let apnsVoip: Bool
    public let apnsFileProvider: Bool
    public let fcm: Bool

    public init(apns: Bool, apnsVoip: Bool, apnsFileProvider: Bool = false, fcm: Bool) {
        self.apns = apns
        self.apnsVoip = apnsVoip
        self.apnsFileProvider = apnsFileProvider
        self.fcm = fcm
    }
}

public struct HealthResponse: Content, Sendable, Equatable {
    public let status: String
    public let version: String
    public let transports: RelayTransportsStatus
}

public struct RelayInfoResponse: Content, Sendable, Equatable {
    public let protocolVersion: Int
    public let version: String
    public let transports: RelayTransportsStatus
    public let apnsAllowSandbox: Bool
    public let maxBatchSize: Int
    public let maxAlertPayloadBytes: Int
    public let maxVoipPayloadBytes: Int
    public let maxFileProviderPayloadBytes: Int
}
