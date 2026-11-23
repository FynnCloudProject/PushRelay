import Foundation
import Vapor

public actor MetricsStore {
    private static let timelineMinutes = 60
    private static let maxLatencySamples = 500
    private static let maxReasonKeys = 64
    private static let latencyBucketBoundsSeconds: [Double] = [
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
    ]

    private struct OutcomeAccumulator {
        var total = 0
        var delivered = 0
        var unregistered = 0
        var failed = 0
    }

    private struct MinuteSlot {
        var minuteEpoch: Int = -1
        var delivered: Int = 0
        var failed: Int = 0
    }

    private let startedAt: Date
    private let now: @Sendable () -> Date
    private let knownTopics: Set<String>

    private var singleRequests = 0
    private var batchRequests = 0
    private var batchItems = 0
    private var totalDispatches = 0
    private var delivered = 0
    private var unregistered = 0
    private var ipRateLimited = 0
    private var tokenRateLimited = 0
    private var validationRejected = 0
    private var upstreamFailed = 0
    private var unsupported = 0

    private var byTransport: [String: OutcomeAccumulator] = [
        "apns": OutcomeAccumulator(),
        "apns-voip": OutcomeAccumulator(),
        "apns-fileprovider": OutcomeAccumulator(),
        "fcm": OutcomeAccumulator(),
    ]
    private var byKind: [String: Int] = ["alert": 0, "background": 0, "voip": 0, "fileprovider": 0]
    private var byEnvironment: [String: Int] = ["production": 0, "sandbox": 0]
    private var byTopic: [String: OutcomeAccumulator] = [:]
    private var reasons: [String: Int] = [:]

    private var ringBuffer: [MinuteSlot] = Array(repeating: MinuteSlot(), count: timelineMinutes)
    private var latencySamples: [Double] = []
    private var latencyCursor = 0
    private var latencyBucketCounts: [Int] = Array(repeating: 0, count: latencyBucketBoundsSeconds.count)
    private var latencyTotalCount = 0
    private var latencyTotalSeconds = 0.0

    public init(
        allowedTopics: Set<String> = [],
        allowedVoIPTopics: Set<String> = [],
        allowedFileProviderTopics: Set<String> = [],
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.startedAt = now()
        self.now = now
        self.knownTopics = allowedTopics.union(allowedVoIPTopics).union(allowedFileProviderTopics)
        for topic in self.knownTopics {
            self.byTopic[topic] = OutcomeAccumulator()
        }
        self.latencySamples.reserveCapacity(Self.maxLatencySamples)
    }

    public func recordSingleHTTPRequest() {
        singleRequests += 1
    }

    public func recordBatchHTTPRequest(itemCount: Int) {
        batchRequests += 1
        batchItems += max(0, itemCount)
    }

    public func recordIPRateLimit() {
        ipRateLimited += 1
        recordReason("ip_rate_limited")
        incrementTimeline(delivered: false)
    }

    public func recordDispatch(
        transport: PushTransport,
        environment: PushEnvironment,
        kind: PushKind?,
        topic: String,
        outcome: PushDeliveryOutcome,
        apnsDurationMs: Double?
    ) {
        totalDispatches += 1
        byEnvironment[environment.rawValue, default: 0] += 1

        let effectiveKind: String
        if let kind {
            effectiveKind = kind.rawValue
        } else {
            switch transport {
            case .apnsVoip: effectiveKind = PushKind.voip.rawValue
            case .apnsFileProvider: effectiveKind = PushKind.fileprovider.rawValue
            case .apns, .fcm: effectiveKind = PushKind.alert.rawValue
            }
        }
        byKind[effectiveKind, default: 0] += 1

        let isDelivered = outcome.response.delivered
        let isUnregistered = !isDelivered && (outcome.response.unregistered || outcome.status == .gone)

        var transportAcc = byTransport[transport.rawValue] ?? OutcomeAccumulator()
        transportAcc.total += 1
        if isDelivered {
            transportAcc.delivered += 1
        } else if isUnregistered {
            transportAcc.unregistered += 1
        } else {
            transportAcc.failed += 1
        }
        byTransport[transport.rawValue] = transportAcc

        if transport == .apns || transport == .apnsVoip || transport == .apnsFileProvider {
            let trimmedTopic = topic.trimmingCharacters(in: .whitespacesAndNewlines)
            let bucketTopic = knownTopics.contains(trimmedTopic) ? trimmedTopic : "disallowed"
            var topicAcc = byTopic[bucketTopic] ?? OutcomeAccumulator()
            topicAcc.total += 1
            if isDelivered {
                topicAcc.delivered += 1
            } else if isUnregistered {
                topicAcc.unregistered += 1
            } else {
                topicAcc.failed += 1
            }
            byTopic[bucketTopic] = topicAcc
        }

        if isDelivered {
            delivered += 1
        } else if isUnregistered {
            unregistered += 1
        } else if outcome.status == .tooManyRequests {
            if outcome.response.reason == "token_rate_limited" {
                tokenRateLimited += 1
            }
        } else if outcome.status == .notImplemented {
            unsupported += 1
        } else if outcome.status == .badRequest || outcome.status == .forbidden || outcome.status == .payloadTooLarge {
            validationRejected += 1
        } else {
            upstreamFailed += 1
        }

        if let reason = outcome.response.reason, !reason.isEmpty {
            recordReason(reason)
        }
        if let apnsDurationMs, apnsDurationMs >= 0 {
            recordLatency(apnsDurationMs)
        }
        incrementTimeline(delivered: isDelivered)
    }

    public func snapshot(
        config: RelayConfig,
        activeIPBuckets: Int,
        activeTokenBuckets: Int
    ) -> MetricsSnapshot {
        let current = now()
        let uptimeSeconds = max(0, Int(current.timeIntervalSince(startedAt)))
        let currentMinute = Int(current.timeIntervalSince1970) / 60

        var timeline: [MinuteMetric] = []
        timeline.reserveCapacity(Self.timelineMinutes)
        var last1m = 0
        var last5m = 0
        var last60m = 0

        for offset in stride(from: Self.timelineMinutes - 1, through: 0, by: -1) {
            let minute = currentMinute - offset
            let idx = ((minute % Self.timelineMinutes) + Self.timelineMinutes) % Self.timelineMinutes
            let slot = ringBuffer[idx]
            let del = (slot.minuteEpoch == minute) ? slot.delivered : 0
            let fail = (slot.minuteEpoch == minute) ? slot.failed : 0
            let sum = del + fail
            if offset == 0 { last1m += sum }
            if offset < 5 { last5m += sum }
            last60m += sum
            timeline.append(MinuteMetric(
                minute: Self.formatISO8601Minute(minute),
                delivered: del,
                failed: fail
            ))
        }

        let apnsConfigured = config.apns.map { !$0.allowedTopics.isEmpty } ?? false
        let apnsVoipConfigured = config.apns.map { !$0.allowedVoIPTopics.isEmpty } ?? false
        let apnsFileProviderConfigured = config.apns.map { !$0.allowedFileProviderTopics.isEmpty } ?? false
        let fcmConfigured = false

        let apnsAcc = byTransport["apns"] ?? OutcomeAccumulator()
        let voipAcc = byTransport["apns-voip"] ?? OutcomeAccumulator()
        let fileProviderAcc = byTransport["apns-fileprovider"] ?? OutcomeAccumulator()
        let fcmAcc = byTransport["fcm"] ?? OutcomeAccumulator()

        let transports: [String: TransportMetrics] = [
            "apns": TransportMetrics(
                enabled: apnsConfigured,
                total: apnsAcc.total,
                delivered: apnsAcc.delivered,
                unregistered: apnsAcc.unregistered,
                failed: apnsAcc.failed
            ),
            "apns-voip": TransportMetrics(
                enabled: apnsVoipConfigured,
                total: voipAcc.total,
                delivered: voipAcc.delivered,
                unregistered: voipAcc.unregistered,
                failed: voipAcc.failed
            ),
            "apns-fileprovider": TransportMetrics(
                enabled: apnsFileProviderConfigured,
                total: fileProviderAcc.total,
                delivered: fileProviderAcc.delivered,
                unregistered: fileProviderAcc.unregistered,
                failed: fileProviderAcc.failed
            ),
            "fcm": TransportMetrics(
                enabled: fcmConfigured,
                total: fcmAcc.total,
                delivered: fcmAcc.delivered,
                unregistered: fcmAcc.unregistered,
                failed: fcmAcc.failed
            ),
        ]

        let topics = byTopic.mapValues { acc in
            TopicMetrics(total: acc.total, delivered: acc.delivered, unregistered: acc.unregistered, failed: acc.failed)
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        return MetricsSnapshot(
            version: RelayConfig.serviceVersion,
            startedAt: formatter.string(from: startedAt),
            uptimeSeconds: uptimeSeconds,
            totals: MetricsTotals(
                dispatches: totalDispatches,
                singleRequests: singleRequests,
                batchRequests: batchRequests,
                batchItems: batchItems,
                delivered: delivered,
                unregistered: unregistered,
                rateLimited: ipRateLimited + tokenRateLimited,
                ipRateLimited: ipRateLimited,
                tokenRateLimited: tokenRateLimited,
                validationRejected: validationRejected,
                upstreamFailed: upstreamFailed,
                unsupported: unsupported
            ),
            throughput: ThroughputSummary(last1m: last1m, last5m: last5m, last60m: last60m),
            latencyMs: computeLatencyMetrics(),
            transports: transports,
            byKind: byKind,
            byEnvironment: byEnvironment,
            byTopic: topics,
            reasons: reasons,
            timeline: timeline,
            rateLimiter: RateLimiterMetrics(
                activeIPBuckets: activeIPBuckets,
                activeTokenBuckets: activeTokenBuckets,
                ipLimitPerMinute: config.rateLimitIPPerMinute,
                tokenLimitPerMinute: config.rateLimitTokenPerMinute
            ),
            config: SafeConfigSummary(
                apnsConfigured: apnsConfigured,
                apnsVoipConfigured: apnsVoipConfigured,
                apnsFileProviderConfigured: apnsFileProviderConfigured,
                fcmConfigured: fcmConfigured,
                sandboxEnabled: config.apns?.allowSandbox ?? false,
                sharedSecretRequired: config.sharedSecret != nil,
                trustProxyHeaders: config.trustProxyHeaders,
                maxBatchSize: config.maxBatchSize,
                allowedTopics: config.apns.map { $0.allowedTopics.sorted() } ?? [],
                allowedVoIPTopics: config.apns.map { $0.allowedVoIPTopics.sorted() } ?? [],
                allowedFileProviderTopics: config.apns.map { $0.allowedFileProviderTopics.sorted() } ?? []
            )
        )
    }

    private func recordReason(_ reason: String) {
        if reasons[reason] != nil || reasons.count < Self.maxReasonKeys {
            reasons[reason, default: 0] += 1
        } else {
            reasons["other", default: 0] += 1
        }
    }

    private func recordLatency(_ ms: Double) {
        if latencySamples.count < Self.maxLatencySamples {
            latencySamples.append(ms)
        } else {
            latencySamples[latencyCursor] = ms
            latencyCursor = (latencyCursor + 1) % Self.maxLatencySamples
        }
        let seconds = ms / 1_000.0
        latencyTotalCount += 1
        latencyTotalSeconds += seconds
        for (idx, bound) in Self.latencyBucketBoundsSeconds.enumerated() where seconds <= bound {
            latencyBucketCounts[idx] += 1
        }
    }

    public func latencyHistogramSnapshot() -> LatencyHistogramSnapshot {
        LatencyHistogramSnapshot(
            boundsSeconds: Self.latencyBucketBoundsSeconds,
            cumulativeCounts: latencyBucketCounts,
            count: latencyTotalCount,
            sumSeconds: latencyTotalSeconds
        )
    }

    private func incrementTimeline(delivered: Bool) {
        let minute = Int(now().timeIntervalSince1970) / 60
        let idx = ((minute % Self.timelineMinutes) + Self.timelineMinutes) % Self.timelineMinutes
        if ringBuffer[idx].minuteEpoch != minute {
            ringBuffer[idx] = MinuteSlot(minuteEpoch: minute, delivered: 0, failed: 0)
        }
        if delivered {
            ringBuffer[idx].delivered += 1
        } else {
            ringBuffer[idx].failed += 1
        }
    }

    private func computeLatencyMetrics() -> LatencyMetrics {
        guard !latencySamples.isEmpty else {
            return LatencyMetrics(samples: 0, avg: nil, p50: nil, p95: nil, max: nil)
        }
        let sorted = latencySamples.sorted()
        let count = sorted.count
        let avg = sorted.reduce(0, +) / Double(count)
        let p50 = sorted[Int(Double(count - 1) * 0.50)]
        let p95 = sorted[Int(Double(count - 1) * 0.95)]
        let maxVal = sorted[count - 1]
        return LatencyMetrics(
            samples: count,
            avg: Self.round1(avg),
            p50: Self.round1(p50),
            p95: Self.round1(p95),
            max: Self.round1(maxVal)
        )
    }

    private static func round1(_ value: Double) -> Double {
        (value * 10).rounded() / 10
    }

    private static func formatISO8601Minute(_ minuteEpoch: Int) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(minuteEpoch * 60))
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .gmt
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute], from: date)
        return String(
            format: "%04d-%02d-%02dT%02d:%02dZ",
            c.year ?? 1970, c.month ?? 1, c.day ?? 1, c.hour ?? 0, c.minute ?? 0
        )
    }
}
