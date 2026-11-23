import Foundation
import Vapor

public final class PushDispatcher: Sendable {
    public static let maxBatchConcurrency = 16

    public let config: RelayConfig
    public let metrics: MetricsStore
    private let apnsService: APNSService?
    private let ipLimiter: SlidingWindowRateLimiter
    private let tokenLimiter: SlidingWindowRateLimiter

    public init(
        config: RelayConfig,
        apnsService: APNSService?,
        metrics: MetricsStore? = nil,
        ipLimiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(),
        tokenLimiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter()
    ) {
        self.config = config
        self.apnsService = apnsService
        self.metrics = metrics ?? MetricsStore(
            allowedTopics: config.apns?.allowedTopics ?? [],
            allowedVoIPTopics: config.apns?.allowedVoIPTopics ?? [],
            allowedFileProviderTopics: config.apns?.allowedFileProviderTopics ?? []
        )
        self.ipLimiter = ipLimiter
        self.tokenLimiter = tokenLimiter
    }

    public var transportsStatus: RelayTransportsStatus {
        RelayTransportsStatus(
            apns: apnsService.map { !$0.config.allowedTopics.isEmpty } ?? false,
            apnsVoip: apnsService.map { !$0.config.allowedVoIPTopics.isEmpty } ?? false,
            apnsFileProvider: apnsService.map { !$0.config.allowedFileProviderTopics.isEmpty } ?? false,
            fcm: false
        )
    }

    public func allowIP(_ clientIP: String, cost: Int = 1) async -> Bool {
        let allowed = await ipLimiter.allow(rawKey: "ip:\(clientIP)", limit: config.rateLimitIPPerMinute, cost: cost)
        if !allowed {
            await metrics.recordIPRateLimit()
        }
        return allowed
    }

    public func metricsSnapshot() async -> MetricsSnapshot {
        let ipBuckets = await ipLimiter.activeKeyCount()
        let tokenBuckets = await tokenLimiter.activeKeyCount()
        return await metrics.snapshot(
            config: config,
            activeIPBuckets: ipBuckets,
            activeTokenBuckets: tokenBuckets
        )
    }

    public func prometheusMetricsText() async -> String {
        let snapshot = await metricsSnapshot()
        let histogram = await metrics.latencyHistogramSnapshot()
        return PrometheusMetricsFormatter.render(snapshot: snapshot, latencyHistogram: histogram)
    }

    public func dispatch(_ request: PushRequest) async -> PushDeliveryOutcome {
        let env = request.environment ?? .production
        let tokenKey = "\(request.transport.rawValue):\(request.token.trimmingCharacters(in: .whitespacesAndNewlines))"
        guard await tokenLimiter.allow(rawKey: tokenKey, limit: config.rateLimitTokenPerMinute) else {
            let outcome = PushDeliveryOutcome(status: .tooManyRequests, response: PushResponse(delivered: false, reason: "token_rate_limited"))
            await metrics.recordDispatch(
                transport: request.transport,
                environment: env,
                kind: request.kind,
                topic: request.target,
                outcome: outcome,
                apnsDurationMs: nil
            )
            return outcome
        }

        let outcome: PushDeliveryOutcome
        var apnsDurationMs: Double?
        switch request.transport {
        case .apns, .apnsVoip, .apnsFileProvider:
            guard let apnsService else {
                outcome = PushDeliveryOutcome(status: .serviceUnavailable, response: PushResponse(delivered: false, reason: "apns_not_configured"))
                break
            }
            let started = ContinuousClock.now
            outcome = await apnsService.send(request)
            let elapsed = ContinuousClock.now - started
            if outcome.response.delivered || outcome.status == .gone || outcome.status == .badGateway || outcome.status == .serviceUnavailable || outcome.status == .tooManyRequests {
                apnsDurationMs = Double(elapsed.components.seconds) * 1_000.0
                    + Double(elapsed.components.attoseconds) / 1_000_000_000_000_000.0
            }
        case .fcm:
            outcome = PushDeliveryOutcome(status: .notImplemented, response: PushResponse(delivered: false, reason: "fcm_not_configured"))
        }

        await metrics.recordDispatch(
            transport: request.transport,
            environment: env,
            kind: request.kind,
            topic: request.target,
            outcome: outcome,
            apnsDurationMs: apnsDurationMs
        )
        return outcome
    }

    public func dispatchBatch(_ messages: [PushRequest]) async -> [PushBatchItemResponse] {
        guard !messages.isEmpty else { return [] }
        var ordered = Array<PushBatchItemResponse?>(repeating: nil, count: messages.count)

        await withTaskGroup(of: PushBatchItemResponse.self) { group in
            var nextIndex = 0
            func enqueueNext() {
                let idx = nextIndex
                nextIndex += 1
                let msg = messages[idx]
                group.addTask { [self] in
                    let outcome = await self.dispatch(msg)
                    return PushBatchItemResponse(
                        index: idx,
                        status: outcome.status.code,
                        delivered: outcome.response.delivered,
                        unregistered: outcome.response.unregistered,
                        apnsId: outcome.response.apnsId,
                        reason: outcome.response.reason
                    )
                }
            }

            while nextIndex < min(Self.maxBatchConcurrency, messages.count) {
                enqueueNext()
            }
            while let result = await group.next() {
                ordered[result.index] = result
                if nextIndex < messages.count {
                    enqueueNext()
                }
            }
        }

        return ordered.compactMap { $0 }
    }
}
