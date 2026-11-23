import Foundation
import Vapor

public struct MetricsTotals: Content, Sendable, Equatable {
    public let dispatches: Int
    public let singleRequests: Int
    public let batchRequests: Int
    public let batchItems: Int
    public let delivered: Int
    public let unregistered: Int
    public let rateLimited: Int
    public let ipRateLimited: Int
    public let tokenRateLimited: Int
    public let validationRejected: Int
    public let upstreamFailed: Int
    public let unsupported: Int
}

public struct ThroughputSummary: Content, Sendable, Equatable {
    public let last1m: Int
    public let last5m: Int
    public let last60m: Int
}

public struct LatencyMetrics: Content, Sendable, Equatable {
    public let samples: Int
    public let avg: Double?
    public let p50: Double?
    public let p95: Double?
    public let max: Double?
}

public struct TransportMetrics: Content, Sendable, Equatable {
    public let enabled: Bool
    public let total: Int
    public let delivered: Int
    public let unregistered: Int
    public let failed: Int
}

public struct TopicMetrics: Content, Sendable, Equatable {
    public let total: Int
    public let delivered: Int
    public let unregistered: Int
    public let failed: Int
}

public struct MinuteMetric: Content, Sendable, Equatable {
    public let minute: String
    public let delivered: Int
    public let failed: Int
}

public struct RateLimiterMetrics: Content, Sendable, Equatable {
    public let activeIPBuckets: Int
    public let activeTokenBuckets: Int
    public let ipLimitPerMinute: Int
    public let tokenLimitPerMinute: Int
}

public struct SafeConfigSummary: Content, Sendable, Equatable {
    public let apnsConfigured: Bool
    public let apnsVoipConfigured: Bool
    public let apnsFileProviderConfigured: Bool
    public let fcmConfigured: Bool
    public let sandboxEnabled: Bool
    public let sharedSecretRequired: Bool
    public let trustProxyHeaders: Bool
    public let maxBatchSize: Int
    public let allowedTopics: [String]
    public let allowedVoIPTopics: [String]
    public let allowedFileProviderTopics: [String]
}

public struct MetricsSnapshot: Content, Sendable, Equatable {
    public let version: String
    public let startedAt: String
    public let uptimeSeconds: Int
    public let totals: MetricsTotals
    public let throughput: ThroughputSummary
    public let latencyMs: LatencyMetrics
    public let transports: [String: TransportMetrics]
    public let byKind: [String: Int]
    public let byEnvironment: [String: Int]
    public let byTopic: [String: TopicMetrics]
    public let reasons: [String: Int]
    public let timeline: [MinuteMetric]
    public let rateLimiter: RateLimiterMetrics
    public let config: SafeConfigSummary
}
