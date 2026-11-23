import APNSCore
import Crypto
import Foundation
import Testing
import Vapor
import VaporTesting
@testable import PushRelay

private actor MockAPNSClient: APNSClientProtocol {
    struct RecordedRequest: Sendable {
        let deviceToken: String
        let headers: [String: String]
        let body: Data
    }

    private(set) var recorded: [RecordedRequest] = []
    private var outcomes: [Result<APNSResponse, any Error>]

    init(outcomes: [Result<APNSResponse, any Error>] = [.success(APNSResponse(apnsID: UUID(uuidString: "11111111-1111-1111-1111-111111111111")))]) {
        self.outcomes = outcomes
    }

    func send(_ request: APNSRequest<some APNSMessage>) async throws -> APNSResponse {
        let body = try JSONEncoder().encode(request.message)
        recorded.append(RecordedRequest(deviceToken: request.deviceToken, headers: request.headers, body: body))
        let next = outcomes.count > 1 ? outcomes.removeFirst() : (outcomes.first ?? .success(APNSResponse()))
        return try next.get()
    }

    func shutdown() async throws {}
}

private func makeAPNSError(status: Int, reason: String) throws -> APNSError {
    let decoded = try JSONDecoder().decode(APNSErrorResponse.self, from: Data(#"{"reason":"\#(reason)"}"#.utf8))
    return APNSError(responseStatus: status, apnsResponse: decoded)
}

private func makeSampleToken(_ fill: String = "ab") -> String {
    String(repeating: fill, count: 32)
}

private func makeTestAPNSConfig(
    privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
    allowSandbox: Bool = true
) throws -> APNSConfig {
    try APNSConfig(
        teamID: "TEAM123456",
        keyID: "TESTKEY123",
        privateKeyPEM: privateKey.pemRepresentation,
        allowedTopics: ["ch.fynncloud.talk", "ch.fynncloud.app"],
        allowedVoIPTopics: ["ch.fynncloud.talk.voip"],
        allowedFileProviderTopics: ["ch.fynncloud.app.pushkit.fileprovider"],
        allowSandbox: allowSandbox
    )
}

private func withConfiguredApp(
    config: RelayConfig,
    production: MockAPNSClient = MockAPNSClient(),
    sandbox: MockAPNSClient = MockAPNSClient(),
    now: @escaping @Sendable () -> Date = { Date(timeIntervalSince1970: 1_763_856_000) },
    _ body: (Application, MockAPNSClient, MockAPNSClient) async throws -> Void
) async throws {
    let app = try await Application.make(.testing)
    do {
        try await configure(app, config: config, productionAPNS: production, sandboxAPNS: sandbox, now: now)
        try await body(app, production, sandbox)
    } catch {
        try? await app.asyncShutdown()
        throw error
    }
    try await app.asyncShutdown()
}

@Suite("PushRelay Tests")
struct PushRelayTests {

    @Test("Config rejects VoIP topics in allowedTopics and non-VoIP topics in allowedVoIPTopics")
    func configTopicValidation() throws {
        let pem = P256.Signing.PrivateKey().pemRepresentation
        #expect(throws: RelayConfigError.self) {
            _ = try APNSConfig(
                teamID: "TEAM123456",
                keyID: "TESTKEY123",
                privateKeyPEM: pem,
                allowedTopics: ["ch.fynncloud.talk.voip"],
                allowedVoIPTopics: []
            )
        }
        #expect(throws: RelayConfigError.self) {
            _ = try APNSConfig(
                teamID: "TEAM123456",
                keyID: "TESTKEY123",
                privateKeyPEM: pem,
                allowedTopics: [],
                allowedVoIPTopics: ["ch.fynncloud.talk"]
            )
        }
        #expect(throws: RelayConfigError.self) {
            _ = try APNSConfig(
                teamID: "TEAM123456",
                keyID: "TESTKEY123",
                privateKeyPEM: pem,
                allowedTopics: ["ch.fynncloud.app.pushkit.fileprovider"],
                allowedVoIPTopics: []
            )
        }
        #expect(throws: RelayConfigError.self) {
            _ = try APNSConfig(
                teamID: "TEAM123456",
                keyID: "TESTKEY123",
                privateKeyPEM: pem,
                allowedTopics: [],
                allowedVoIPTopics: [],
                allowedFileProviderTopics: ["ch.fynncloud.app"]
            )
        }
    }

    @Test("GET /health and GET /v1/info report enabled transports")
    func healthAndInfoEndpoints() async throws {
        let config = RelayConfig(apns: try makeTestAPNSConfig(allowSandbox: true))
        try await withConfiguredApp(config: config) { app, _, _ in
            try await app.testing().test(.GET, "health") { res async throws in
                #expect(res.status == .ok)
                let body = try res.content.decode(HealthResponse.self)
                #expect(body.status == "ok")
                #expect(body.transports == RelayTransportsStatus(apns: true, apnsVoip: true, apnsFileProvider: true, fcm: false))
            }

            try await app.testing().test(.GET, "v1/info") { res async throws in
                #expect(res.status == .ok)
                let info = try res.content.decode(RelayInfoResponse.self)
                #expect(info.protocolVersion == 1)
                #expect(info.apnsAllowSandbox == true)
                #expect(info.maxAlertPayloadBytes == 4_096)
                #expect(info.maxVoipPayloadBytes == 5_120)
                #expect(info.maxFileProviderPayloadBytes == 4_096)
            }
        }
    }

    @Test("FileProvider push sends apns-push-type fileprovider, priority 5, and root container-identifier/domain payload")
    func fileProviderPush() async throws {
        let token = makeSampleToken("56")
        let fixedNow = Date(timeIntervalSince1970: 1_763_856_000)
        let config = RelayConfig(apns: try makeTestAPNSConfig(allowSandbox: true))

        try await withConfiguredApp(config: config, now: { fixedNow }) { app, production, sandbox in
            let reqBody = PushRequest(
                transport: .apnsFileProvider,
                environment: .production,
                target: "ch.fynncloud.app.pushkit.fileprovider",
                token: token,
                kind: .fileprovider,
                ttlSeconds: 3_600,
                domain: "ch.fynncloud.app.FynnCloudFileProvider.user-123"
            )

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(reqBody)
            }) { res async throws in
                #expect(res.status == .ok)
                let reply = try res.content.decode(PushResponse.self)
                #expect(reply.delivered == true)
                #expect(reply.unregistered == false)
            }

            let sent = try #require(await production.recorded.first)
            #expect(await sandbox.recorded.isEmpty)
            #expect(sent.deviceToken == token)
            #expect(sent.headers["apns-topic"] == "ch.fynncloud.app.pushkit.fileprovider")
            #expect(sent.headers["apns-push-type"] == "fileprovider")
            #expect(sent.headers["apns-priority"] == "5")
            #expect(sent.headers["apns-expiration"] == String(1_763_859_600))
            #expect(sent.headers["apns-collapse-id"] == nil)

            let payloadObj = try #require(try JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            #expect(payloadObj["aps"] == nil)
            #expect(payloadObj["container-identifier"] as? String == "NSFileProviderWorkingSetContainerItemIdentifier")
            #expect(payloadObj["domain"] as? String == "ch.fynncloud.app.FynnCloudFileProvider.user-123")

            // Disallowed FileProvider topic is rejected
            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apnsFileProvider,
                    target: "com.evil.app.pushkit.fileprovider",
                    token: token
                ))
            }) { res async throws in
                #expect(res.status == .forbidden)
                #expect(try res.content.decode(PushResponse.self).reason == "topic_not_allowed")
            }

            // Wrong kind for FileProvider transport is rejected
            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apnsFileProvider,
                    target: "ch.fynncloud.app.pushkit.fileprovider",
                    token: token,
                    kind: .alert
                ))
            }) { res async throws in
                #expect(res.status == .badRequest)
                #expect(try res.content.decode(PushResponse.self).reason == "apns_fileprovider_requires_fileprovider_kind")
            }
        }
    }

    @Test("PushKit VoIP push forwards HPKE ciphertext with VoIP headers and round-trips decryption")
    func voipPushAndHPKERoundTrip() async throws {
        let devicePrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
        let info = Data("fynncloud-push-v1".utf8)
        let plaintext = Data(#"{"kind":"call","callUUID":"550e8400-e29b-41d4-a716-446655440000","callerName":"Anna","isVideo":true}"#.utf8)

        var sender = try HPKE.Sender(recipientKey: devicePrivateKey.publicKey, ciphersuite: ciphersuite, info: info)
        let sealed = try sender.seal(plaintext)
        let ciphertextB64 = (sender.encapsulatedKey + sealed).base64EncodedString()

        let token = makeSampleToken("de")
        let fixedNow = Date(timeIntervalSince1970: 1_763_856_000)
        let config = RelayConfig(apns: try makeTestAPNSConfig())

        try await withConfiguredApp(config: config, now: { fixedNow }) { app, production, sandbox in
            let reqBody = PushRequest(
                transport: .apnsVoip,
                environment: .production,
                target: "ch.fynncloud.talk.voip",
                token: token,
                kind: .voip,
                urgency: .call,
                ttlSeconds: 45,
                collapseId: "ignored-for-voip",
                keyId: "a3f91b02",
                ciphertext: ciphertextB64
            )

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(reqBody)
            }) { res async throws in
                #expect(res.status == .ok)
                let reply = try res.content.decode(PushResponse.self)
                #expect(reply.delivered == true)
                #expect(reply.unregistered == false)
                #expect(reply.apnsId == "11111111-1111-1111-1111-111111111111")
            }

            let sent = try #require(await production.recorded.first)
            #expect(await sandbox.recorded.isEmpty)
            #expect(sent.deviceToken == token)
            #expect(sent.headers["apns-topic"] == "ch.fynncloud.talk.voip")
            #expect(sent.headers["apns-push-type"] == "voip")
            #expect(sent.headers["apns-priority"] == "10")
            #expect(sent.headers["apns-expiration"] == String(1_763_856_045))
            #expect(sent.headers["apns-collapse-id"] == nil)

            let payloadObj = try #require(try JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            #expect(payloadObj["aps"] == nil)
            #expect(payloadObj["k"] as? String == "a3f91b02")
            let deliveredCiphertext = try #require(payloadObj["c"] as? String)
            let deliveredRaw = try #require(Data(base64Encoded: deliveredCiphertext))

            var recipient = try HPKE.Recipient(
                privateKey: devicePrivateKey,
                ciphersuite: ciphersuite,
                info: info,
                encapsulatedKey: deliveredRaw.prefix(32)
            )
            #expect(try recipient.open(deliveredRaw.dropFirst(32)) == plaintext)
        }
    }

    @Test("Standard APNs alert sets mutable-content, time-sensitive for call urgency, sandbox routing, and collapse-id")
    func standardAlertAndSandboxRouting() async throws {
        let token = makeSampleToken("12")
        let config = RelayConfig(apns: try makeTestAPNSConfig(allowSandbox: true))

        try await withConfiguredApp(config: config) { app, production, sandbox in
            let reqBody = PushRequest(
                transport: .apns,
                environment: .sandbox,
                target: "ch.fynncloud.talk",
                token: token,
                kind: .alert,
                urgency: .call,
                ttlSeconds: 45,
                collapseId: "hash-room-123",
                keyId: "mac-k1",
                ciphertext: Data("opaque-ciphertext".utf8).base64EncodedString()
            )

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(reqBody)
            }) { res async throws in
                #expect(res.status == .ok)
            }

            #expect(await production.recorded.isEmpty)
            let sent = try #require(await sandbox.recorded.first)
            #expect(sent.deviceToken == token)
            #expect(sent.headers["apns-topic"] == "ch.fynncloud.talk")
            #expect(sent.headers["apns-push-type"] == "alert")
            #expect(sent.headers["apns-priority"] == "10")
            #expect(sent.headers["apns-collapse-id"] == "hash-room-123")

            let payloadObj = try #require(try JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            let aps = try #require(payloadObj["aps"] as? [String: Any])
            #expect(aps["mutable-content"] as? Int == 1)
            #expect(aps["interruption-level"] as? String == "time-sensitive")
        }
    }

    @Test("Background silent push enforces apns-priority 5 and content-available 1")
    func backgroundSilentPushEnforcesPriorityFive() async throws {
        let token = makeSampleToken("34")
        let config = RelayConfig(apns: try makeTestAPNSConfig())

        try await withConfiguredApp(config: config) { app, production, _ in
            let reqBody = PushRequest(
                transport: .apns,
                environment: .production,
                target: "ch.fynncloud.talk",
                token: token,
                kind: .background,
                urgency: .high,
                ttlSeconds: 30,
                collapseId: "dismiss-1",
                keyId: "k1",
                ciphertext: Data("dismiss-ring".utf8).base64EncodedString()
            )

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(reqBody)
            }) { res async throws in
                #expect(res.status == .ok)
            }

            let sent = try #require(await production.recorded.first)
            #expect(sent.headers["apns-push-type"] == "background")
            #expect(sent.headers["apns-priority"] == "5")
            #expect(sent.headers["apns-collapse-id"] == "dismiss-1")

            let payloadObj = try #require(try JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
            let aps = try #require(payloadObj["aps"] as? [String: Any])
            #expect(aps["content-available"] as? Int == 1)
            #expect(aps["alert"] == nil)
        }
    }

    @Test("Validation blocks disallowed topics, disabled sandbox, bad tokens, and oversized payloads")
    func validationRules() async throws {
        let config = RelayConfig(apns: try makeTestAPNSConfig(allowSandbox: false))
        let validCT = Data("ok".utf8).base64EncodedString()

        try await withConfiguredApp(config: config) { app, production, sandbox in
            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apns, target: "com.evil.app", token: makeSampleToken(), keyId: "k1", ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .forbidden)
                #expect(try res.content.decode(PushResponse.self).reason == "topic_not_allowed")
            }

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apnsVoip, target: "ch.fynncloud.talk", token: makeSampleToken(), keyId: "k1", ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .forbidden)
            }

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apns, environment: .sandbox, target: "ch.fynncloud.talk", token: makeSampleToken(), keyId: "k1", ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .forbidden)
                #expect(try res.content.decode(PushResponse.self).reason == "sandbox_disabled")
            }

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apns, target: "ch.fynncloud.talk", token: "../evil/path", keyId: "k1", ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .badRequest)
                #expect(try res.content.decode(PushResponse.self).reason == "invalid_apns_token")
            }

            let hugeCT = Data(repeating: 0xAA, count: 3_500).base64EncodedString()
            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apns, target: "ch.fynncloud.talk", token: makeSampleToken(), keyId: "k1", ciphertext: hugeCT
                ))
            }) { res async throws in
                #expect(res.status == .payloadTooLarge)
            }

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .fcm, target: "ch.fynncloud.talk", token: "fcm-token-123", keyId: "k1", ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .notImplemented)
                #expect(try res.content.decode(PushResponse.self).reason == "fcm_not_configured")
            }

            #expect(await production.recorded.isEmpty)
            #expect(await sandbox.recorded.isEmpty)
        }
    }

    @Test("APNs error mapping flags 410/BadDeviceToken as unregistered and relay credential errors as 502")
    func apnsErrorMapping() async throws {
        let config = RelayConfig(apns: try makeTestAPNSConfig())
        let validCT = Data("cipher".utf8).base64EncodedString()
        let baseReq = PushRequest(
            transport: .apns, target: "ch.fynncloud.talk", token: makeSampleToken(), keyId: "k1", ciphertext: validCT
        )

        let mock = MockAPNSClient(outcomes: [
            .failure(try makeAPNSError(status: 410, reason: "Unregistered")),
            .failure(try makeAPNSError(status: 400, reason: "BadDeviceToken")),
            .failure(try makeAPNSError(status: 400, reason: "InvalidProviderToken")),
        ])
        try await withConfiguredApp(config: config, production: mock) { app, _, _ in
            try await app.testing().test(.POST, "v1/push", beforeRequest: { try $0.content.encode(baseReq) }) { res async throws in
                #expect(res.status == .gone)
                let body = try res.content.decode(PushResponse.self)
                #expect(body.unregistered == true)
                #expect(body.reason == "Unregistered")
            }

            try await app.testing().test(.POST, "v1/push", beforeRequest: { try $0.content.encode(baseReq) }) { res async throws in
                #expect(res.status == .gone)
                let body = try res.content.decode(PushResponse.self)
                #expect(body.unregistered == true)
                #expect(body.reason == "BadDeviceToken")
            }

            try await app.testing().test(.POST, "v1/push", beforeRequest: { try $0.content.encode(baseReq) }) { res async throws in
                #expect(res.status == .badGateway)
                let body = try res.content.decode(PushResponse.self)
                #expect(body.unregistered == false)
                #expect(body.reason == "InvalidProviderToken")
            }
        }
    }

    @Test("Batch dispatch preserves order and reports per-item status")
    func batchDispatch() async throws {
        let config = RelayConfig(apns: try makeTestAPNSConfig())
        let validCT = Data("cipher".utf8).base64EncodedString()
        let mock = MockAPNSClient(outcomes: [
            .success(APNSResponse(apnsID: UUID(uuidString: "22222222-2222-2222-2222-222222222222"))),
            .failure(try makeAPNSError(status: 410, reason: "Unregistered")),
        ])

        try await withConfiguredApp(config: config, production: mock) { app, _, _ in
            let batch = PushBatchRequest(messages: [
                PushRequest(transport: .apnsVoip, target: "ch.fynncloud.talk.voip", token: makeSampleToken("aa"), keyId: "k1", ciphertext: validCT),
                PushRequest(transport: .apns, target: "ch.fynncloud.talk", token: makeSampleToken("bb"), keyId: "k2", ciphertext: validCT),
                PushRequest(transport: .fcm, target: "ch.fynncloud.talk", token: "fcm-tok", keyId: "k3", ciphertext: validCT),
            ])

            try await app.testing().test(.POST, "v1/push/batch", beforeRequest: { req in
                try req.content.encode(batch)
            }) { res async throws in
                #expect(res.status == .ok)
                let reply = try res.content.decode(PushBatchResponse.self)
                #expect(reply.results.count == 3)
                #expect(reply.results.map(\.index) == [0, 1, 2])
                #expect(reply.results[2].status == 501)
                #expect(reply.results[2].reason == "fcm_not_configured")
                #expect(Set(reply.results.prefix(2).map(\.status)) == [200, 410])
            }
        }
    }

    @Test("Optional shared secret and per-token rate limit are enforced")
    func sharedSecretAndRateLimit() async throws {
        let config = RelayConfig(
            apns: try makeTestAPNSConfig(),
            sharedSecret: "super-secret-relay-key",
            rateLimitIPPerMinute: 100,
            rateLimitTokenPerMinute: 2
        )
        let validCT = Data("cipher".utf8).base64EncodedString()
        let reqBody = PushRequest(
            transport: .apns, target: "ch.fynncloud.talk", token: makeSampleToken("ff"), keyId: "k1", ciphertext: validCT
        )

        try await withConfiguredApp(config: config) { app, _, _ in
            try await app.testing().test(.POST, "v1/push", beforeRequest: { try $0.content.encode(reqBody) }) { res async throws in
                #expect(res.status == .unauthorized)
            }

            for expectedStatus in [HTTPResponseStatus.ok, .ok, .tooManyRequests] {
                try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                    req.headers.bearerAuthorization = BearerAuthorization(token: "super-secret-relay-key")
                    try req.content.encode(reqBody)
                }) { res async throws in
                    #expect(res.status == expectedStatus)
                }
            }
        }
    }

    @Test("Admin UI is disabled by default and AdminConfig enforces minimum password length")
    func adminDisabledByDefaultAndPasswordPolicy() async throws {
        #expect(throws: RelayConfigError.self) {
            _ = try AdminConfig(password: "short")
        }

        let config = RelayConfig(apns: try makeTestAPNSConfig(), admin: nil)
        try await withConfiguredApp(config: config) { app, _, _ in
            try await app.testing().test(.GET, "admin") { res async throws in
                #expect(res.status == .notFound)
            }
            try await app.testing().test(.GET, "admin/metrics.json") { res async throws in
                #expect(res.status == .notFound)
            }
            try await app.testing().test(.GET, "metrics") { res async throws in
                #expect(res.status == .notFound)
            }
        }
    }

    @Test("Prometheus /metrics and /admin/metrics enforce Bearer auth and emit valid exposition format")
    func prometheusMetricsEndpoint() async throws {
        let scrapeToken = "prom-scrape-secret-token"
        let adminPassword = "correct-horse-battery-staple"
        let adminConfig = try AdminConfig(password: adminPassword, secureCookie: true)
        let config = RelayConfig(
            apns: try makeTestAPNSConfig(),
            admin: adminConfig,
            metricsBearerToken: scrapeToken
        )
        let mock = MockAPNSClient(outcomes: [
            .success(APNSResponse(apnsID: UUID(uuidString: "44444444-4444-4444-4444-444444444444"))),
            .failure(try makeAPNSError(status: 410, reason: "Unregistered")),
        ])

        try await withConfiguredApp(config: config, production: mock) { app, _, _ in
            let validCT = Data("opaque".utf8).base64EncodedString()
            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apnsFileProvider,
                    target: "ch.fynncloud.app.pushkit.fileprovider",
                    token: makeSampleToken("aa"),
                    domain: "ch.fynncloud.app.FynnCloudFileProvider.u1"
                ))
            }) { res async throws in
                #expect(res.status == .ok)
            }
            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apns,
                    target: "ch.fynncloud.talk",
                    token: makeSampleToken("bb"),
                    keyId: "k1",
                    ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .gone)
            }

            // Unauthenticated /metrics -> 401
            try await app.testing().test(.GET, "metrics") { res async throws in
                #expect(res.status == .unauthorized)
                #expect(res.headers.first(name: .wwwAuthenticate)?.contains("Bearer") == true)
            }

            // Dedicated METRICS_BEARER_TOKEN works on /metrics
            try await app.testing().test(.GET, "metrics", beforeRequest: { req in
                req.headers.bearerAuthorization = BearerAuthorization(token: scrapeToken)
            }) { res async throws in
                #expect(res.status == .ok)
                #expect(res.headers.first(name: .contentType) == PrometheusMetricsFormatter.contentType)
                let text = res.body.string
                #expect(text.contains("# TYPE push_relay_dispatches_total counter"))
                #expect(text.contains("push_relay_dispatches_total 2"))
                #expect(text.contains("push_relay_dispatches_by_outcome_total{outcome=\"delivered\"} 1"))
                #expect(text.contains("push_relay_dispatches_by_outcome_total{outcome=\"unregistered\"} 1"))
                #expect(text.contains("push_relay_transport_enabled{transport=\"apns-fileprovider\"} 1"))
                #expect(text.contains("push_relay_transport_dispatches_total{transport=\"apns-fileprovider\",outcome=\"delivered\"} 1"))
                #expect(text.contains("push_relay_kind_dispatches_total{kind=\"fileprovider\"} 1"))
                #expect(text.contains("push_relay_topic_dispatches_total{topic=\"ch.fynncloud.app.pushkit.fileprovider\",outcome=\"delivered\"} 1"))
                #expect(text.contains("push_relay_reasons_total{reason=\"Unregistered\"} 1"))
                #expect(text.contains("# TYPE push_relay_apns_duration_seconds histogram"))
                #expect(text.contains("push_relay_apns_duration_seconds_bucket{le=\"+Inf\"} 2"))
                #expect(text.contains("push_relay_apns_duration_seconds_count 2"))
            }

            // ADMIN_PASSWORD also works on /admin/metrics
            try await app.testing().test(.GET, "admin/metrics", beforeRequest: { req in
                req.headers.bearerAuthorization = BearerAuthorization(token: adminPassword)
            }) { res async throws in
                #expect(res.status == .ok)
                #expect(res.headers.first(name: .contentType) == PrometheusMetricsFormatter.contentType)
                #expect(res.body.string.contains("push_relay_dispatches_total 2"))
            }
        }
    }

    @Test("Admin login, security headers, CSRF, Fetch Metadata, metrics dashboard, JSON, and logout")
    func adminWebUIAndSecurity() async throws {
        let adminPassword = "correct-horse-battery-staple"
        let adminConfig = try AdminConfig(password: adminPassword, secureCookie: true, loginRateLimitPer5Min: 5)
        let config = RelayConfig(apns: try makeTestAPNSConfig(), admin: adminConfig)
        let mock = MockAPNSClient(outcomes: [
            .success(APNSResponse(apnsID: UUID(uuidString: "33333333-3333-3333-3333-333333333333"))),
            .failure(try makeAPNSError(status: 410, reason: "Unregistered")),
        ])

        try await withConfiguredApp(config: config, production: mock) { app, _, _ in
            let validCT = Data("top-secret-ciphertext".utf8).base64EncodedString()
            let sampleToken = makeSampleToken("cd")

            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apnsVoip, target: "ch.fynncloud.talk.voip", token: sampleToken, keyId: "k1", ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .ok)
            }
            try await app.testing().test(.POST, "v1/push", beforeRequest: { req in
                try req.content.encode(PushRequest(
                    transport: .apns, target: "ch.fynncloud.talk", token: makeSampleToken("ef"), keyId: "k2", ciphertext: validCT
                ))
            }) { res async throws in
                #expect(res.status == .gone)
            }

            try await app.testing().test(.GET, "admin") { res async throws in
                #expect(res.status == .seeOther)
                #expect(res.headers.first(name: .location) == "/admin/login")
            }
            try await app.testing().test(.GET, "admin/metrics.json") { res async throws in
                #expect(res.status == .unauthorized)
            }

            try await app.testing().test(.POST, "admin/login", beforeRequest: { req in
                req.headers.replaceOrAdd(name: "Sec-Fetch-Site", value: "cross-site")
                req.headers.replaceOrAdd(name: "Sec-Fetch-Mode", value: "cors")
                req.headers.replaceOrAdd(name: "Sec-Fetch-Dest", value: "empty")
            }) { res async throws in
                #expect(res.status == .forbidden)
                #expect(res.headers.first(name: .vary)?.contains("Sec-Fetch-Site") == true)
            }

            var loginCSRF = ""
            try await app.testing().test(.GET, "admin/login", beforeRequest: { req in
                req.headers.replaceOrAdd(name: "Sec-Fetch-Site", value: "cross-site")
                req.headers.replaceOrAdd(name: "Sec-Fetch-Mode", value: "navigate")
                req.headers.replaceOrAdd(name: "Sec-Fetch-Dest", value: "document")
            }) { res async throws in
                #expect(res.status == .ok)
                let html = res.body.string
                #expect(html.contains("Sign In"))
                #expect(html.contains(#"autocomplete="current-password""#))
                #expect(html.contains(#"<meta name="color-scheme" content="light dark">"#))

                let csp = try #require(res.headers.first(name: "Content-Security-Policy"))
                #expect(csp.contains("frame-ancestors 'none'"))
                #expect(csp.contains("'strict-dynamic'"))
                #expect(csp.contains("require-trusted-types-for 'script'"))
                #expect(res.headers.first(name: "X-Frame-Options") == "DENY")
                #expect(res.headers.first(name: "X-Content-Type-Options") == "nosniff")
                #expect(res.headers.first(name: "Cross-Origin-Opener-Policy") == "same-origin")
                #expect(res.headers.first(name: "Cross-Origin-Resource-Policy") == "same-origin")
                #expect(res.headers.first(name: "Strict-Transport-Security")?.contains("max-age=") == true)

                loginCSRF = try #require(Self.extractHiddenInput(named: "_csrf", from: html))
            }

            try await app.testing().test(.POST, "admin/login", beforeRequest: { req in
                try req.content.encode(["password": adminPassword], as: .urlEncodedForm)
            }) { res async throws in
                #expect(res.status == .forbidden)
            }

            try await app.testing().test(.POST, "admin/login", beforeRequest: { req in
                try req.content.encode(["password": "wrong-password-123", "_csrf": loginCSRF], as: .urlEncodedForm)
            }) { res async throws in
                #expect(res.status == .unauthorized)
                #expect(res.body.string.contains("Invalid password."))
            }

            var sessionCookieValue = ""
            try await app.testing().test(.POST, "admin/login", beforeRequest: { req in
                try req.content.encode(["password": adminPassword, "_csrf": loginCSRF], as: .urlEncodedForm)
            }) { res async throws in
                #expect(res.status == .seeOther)
                #expect(res.headers.first(name: .location) == "/admin")
                let setCookie = try #require(res.headers.first(name: .setCookie))
                #expect(setCookie.contains("__Host-push_admin="))
                #expect(setCookie.contains("HttpOnly"))
                #expect(setCookie.contains("Secure"))
                #expect(setCookie.contains("SameSite=Lax"))
                #expect(setCookie.contains("Path=/"))
                sessionCookieValue = try #require(res.headers.setCookie?["__Host-push_admin"]?.string)
            }

            var logoutCSRF = ""
            try await app.testing().test(.GET, "admin", beforeRequest: { req in
                req.headers.replaceOrAdd(name: .cookie, value: "__Host-push_admin=\(sessionCookieValue)")
            }) { res async throws in
                #expect(res.status == .ok)
                let html = res.body.string
                #expect(html.contains("FynnCloud Push"))
                #expect(html.contains("APNs VoIP"))
                #expect(html.contains("FCM"))
                #expect(html.contains("ch.fynncloud.talk.voip"))
                #expect(html.contains("Unregistered"))
                #expect(!html.contains(sampleToken))
                #expect(!html.contains(validCT))
                #expect(!html.contains(adminPassword))
                logoutCSRF = try #require(Self.extractHiddenInput(named: "_csrf", from: html))
            }

            try await app.testing().test(.GET, "admin/assets/admin.css") { res async throws in
                #expect(res.status == .ok)
                #expect(res.headers.first(name: .contentType)?.contains("text/css") == true)
                #expect(res.body.string.contains("color-scheme: light dark"))
            }

            try await app.testing().test(.GET, "admin/metrics.json", beforeRequest: { req in
                req.headers.bearerAuthorization = BearerAuthorization(token: adminPassword)
            }) { res async throws in
                #expect(res.status == .ok)
                let rawJSON = res.body.string
                #expect(!rawJSON.contains("barX"))
                #expect(!rawJSON.contains("deliveredHeight"))
                #expect(!rawJSON.contains("healthTitle"))

                let snap = try res.content.decode(MetricsSnapshot.self)
                #expect(snap.transports["apns"]?.enabled == true)
                #expect(snap.transports["apns-voip"]?.enabled == true)
                #expect(snap.transports["apns-fileprovider"]?.enabled == true)
                #expect(snap.transports["fcm"]?.enabled == false)
                #expect(snap.totals.dispatches == 2)
                #expect(snap.totals.delivered == 1)
                #expect(snap.totals.unregistered == 1)
                #expect(snap.totals.singleRequests == 2)
                #expect(snap.config.apnsConfigured == true)
                #expect(snap.config.apnsVoipConfigured == true)
                #expect(snap.config.apnsFileProviderConfigured == true)
                #expect(snap.config.fcmConfigured == false)
            }

            try await app.testing().test(.POST, "admin/logout", beforeRequest: { req in
                req.headers.replaceOrAdd(name: .cookie, value: "__Host-push_admin=\(sessionCookieValue)")
                try req.content.encode(["_csrf": "bogus"], as: .urlEncodedForm)
            }) { res async throws in
                #expect(res.status == .forbidden)
            }

            try await app.testing().test(.POST, "admin/logout", beforeRequest: { req in
                req.headers.replaceOrAdd(name: .cookie, value: "__Host-push_admin=\(sessionCookieValue)")
                try req.content.encode(["_csrf": logoutCSRF], as: .urlEncodedForm)
            }) { res async throws in
                #expect(res.status == .seeOther)
                #expect(res.headers.first(name: .location) == "/admin/login")
                #expect(res.headers.first(name: "Clear-Site-Data") == #""cookies", "storage", "cache""#)
            }
        }
    }

    private static func extractHiddenInput(named name: String, from html: String) -> String? {
        let marker = #"name="\#(name)" value=""#
        guard let startRange = html.range(of: marker) else { return nil }
        let rest = html[startRange.upperBound...]
        guard let endQuote = rest.firstIndex(of: "\"") else { return nil }
        return String(rest[..<endQuote])
    }
}
