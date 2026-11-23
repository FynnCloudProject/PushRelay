import Crypto
import Foundation
import Vapor

public struct PushController: RouteCollection, Sendable {
    public init() {}

    public func boot(routes: any RoutesBuilder) throws {
        routes.get("health", use: health)
        routes.get("metrics", use: prometheusMetrics)

        let v1 = routes.grouped("v1")
        v1.get("info", use: info)
        v1.post("push", use: pushSingle)
        v1.post("push", "batch", use: pushBatch)
    }

    @Sendable
    func prometheusMetrics(req: Request) async throws -> Response {
        let dispatcher = req.application.pushDispatcher
        let acceptedTokens = [dispatcher.config.metricsBearerToken, dispatcher.config.admin?.password]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
        guard !acceptedTokens.isEmpty else {
            throw Abort(.notFound)
        }
        guard let presented = req.headers.bearerAuthorization?.token,
              acceptedTokens.contains(where: { Self.constantTimeEquals(presented, $0) })
        else {
            var headers = HTTPHeaders()
            headers.replaceOrAdd(name: .wwwAuthenticate, value: "Bearer realm=\"metrics\"")
            headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            return Response(status: .unauthorized, headers: headers)
        }

        let body = await dispatcher.prometheusMetricsText()
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: PrometheusMetricsFormatter.contentType)
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        return Response(status: .ok, headers: headers, body: .init(string: body))
    }

    @Sendable
    func health(req: Request) -> HealthResponse {
        HealthResponse(
            status: "ok",
            version: RelayConfig.serviceVersion,
            transports: req.application.pushDispatcher.transportsStatus
        )
    }

    @Sendable
    func info(req: Request) -> RelayInfoResponse {
        let dispatcher = req.application.pushDispatcher
        return RelayInfoResponse(
            protocolVersion: 1,
            version: RelayConfig.serviceVersion,
            transports: dispatcher.transportsStatus,
            apnsAllowSandbox: dispatcher.config.apns?.allowSandbox ?? false,
            maxBatchSize: dispatcher.config.maxBatchSize,
            maxAlertPayloadBytes: APNSService.maxAlertPayloadBytes,
            maxVoipPayloadBytes: APNSService.maxVoIPPayloadBytes,
            maxFileProviderPayloadBytes: APNSService.maxFileProviderPayloadBytes
        )
    }

    @Sendable
    func pushSingle(req: Request) async throws -> Response {
        let dispatcher = req.application.pushDispatcher
        try enforceSharedSecret(req, expected: dispatcher.config.sharedSecret)

        let clientIP = req.clientIP(trustProxyHeaders: dispatcher.config.trustProxyHeaders)
        guard await dispatcher.allowIP(clientIP, cost: 1) else {
            return try encodeJSON(status: .tooManyRequests, body: PushResponse(delivered: false, reason: "ip_rate_limited"))
        }

        let payload = try req.content.decode(PushRequest.self)
        await dispatcher.metrics.recordSingleHTTPRequest()
        let outcome = await dispatcher.dispatch(payload)
        return try encodeJSON(status: outcome.status, body: outcome.response)
    }

    @Sendable
    func pushBatch(req: Request) async throws -> Response {
        let dispatcher = req.application.pushDispatcher
        try enforceSharedSecret(req, expected: dispatcher.config.sharedSecret)

        let batch = try req.content.decode(PushBatchRequest.self)
        guard !batch.messages.isEmpty else {
            throw Abort(.badRequest, reason: "'messages' must contain at least one item.")
        }
        guard batch.messages.count <= dispatcher.config.maxBatchSize else {
            throw Abort(.payloadTooLarge, reason: "At most \(dispatcher.config.maxBatchSize) messages per batch.")
        }

        let clientIP = req.clientIP(trustProxyHeaders: dispatcher.config.trustProxyHeaders)
        guard await dispatcher.allowIP(clientIP, cost: batch.messages.count) else {
            return try encodeJSON(status: .tooManyRequests, body: PushResponse(delivered: false, reason: "ip_rate_limited"))
        }

        await dispatcher.metrics.recordBatchHTTPRequest(itemCount: batch.messages.count)
        let results = await dispatcher.dispatchBatch(batch.messages)
        return try encodeJSON(status: .ok, body: PushBatchResponse(results: results))
    }

    private func enforceSharedSecret(_ req: Request, expected: String?) throws {
        guard let expected, !expected.isEmpty else { return }
        guard let presented = req.headers.bearerAuthorization?.token,
              Self.constantTimeEquals(presented, expected)
        else {
            throw Abort(.unauthorized, reason: "Missing or invalid relay authorization token.")
        }
    }

    private static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let a = Array(SHA256.hash(data: Data(lhs.utf8)))
        let b = Array(SHA256.hash(data: Data(rhs.utf8)))
        var diff: UInt8 = 0
        for i in 0 ..< a.count {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }

    private func encodeJSON<T: Encodable>(status: HTTPResponseStatus, body: T) throws -> Response {
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: "application/json; charset=utf-8")
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return Response(status: status, headers: headers, body: .init(data: try JSONEncoder().encode(body)))
    }
}

extension Request {
    func clientIP(trustProxyHeaders: Bool) -> String {
        if trustProxyHeaders {
            if let forwarded = headers.first(name: "X-Forwarded-For")?
                .split(separator: ",")
                .first
                .map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
               !forwarded.isEmpty
            {
                return forwarded
            }
            if let realIP = headers.first(name: "X-Real-IP")?.trimmingCharacters(in: .whitespacesAndNewlines),
               !realIP.isEmpty
            {
                return realIP
            }
        }
        return peerAddress?.ipAddress ?? "unknown"
    }
}
