import Foundation

public struct LatencyHistogramSnapshot: Sendable, Equatable {
    public let boundsSeconds: [Double]
    public let cumulativeCounts: [Int]
    public let count: Int
    public let sumSeconds: Double

    public init(boundsSeconds: [Double], cumulativeCounts: [Int], count: Int, sumSeconds: Double) {
        self.boundsSeconds = boundsSeconds
        self.cumulativeCounts = cumulativeCounts
        self.count = count
        self.sumSeconds = sumSeconds
    }
}

public enum PrometheusMetricsFormatter {
    public static let contentType = "text/plain; version=0.0.4; charset=utf-8"

    public static func render(
        snapshot: MetricsSnapshot,
        latencyHistogram: LatencyHistogramSnapshot
    ) -> String {
        var lines: [String] = []
        lines.reserveCapacity(128)

        lines.append("# HELP push_relay_info Static build and version information for FynnCloud PushRelay.")
        lines.append("# TYPE push_relay_info gauge")
        lines.append("push_relay_info{version=\"\(escapeLabel(snapshot.version))\"} 1")

        lines.append("# HELP push_relay_uptime_seconds Process uptime in seconds.")
        lines.append("# TYPE push_relay_uptime_seconds gauge")
        lines.append("push_relay_uptime_seconds \(snapshot.uptimeSeconds)")

        lines.append("# HELP push_relay_http_requests_total Total authenticated push HTTP requests received.")
        lines.append("# TYPE push_relay_http_requests_total counter")
        lines.append("push_relay_http_requests_total{endpoint=\"single\"} \(snapshot.totals.singleRequests)")
        lines.append("push_relay_http_requests_total{endpoint=\"batch\"} \(snapshot.totals.batchRequests)")

        lines.append("# HELP push_relay_batch_items_total Total push items submitted via /v1/push/batch.")
        lines.append("# TYPE push_relay_batch_items_total counter")
        lines.append("push_relay_batch_items_total \(snapshot.totals.batchItems)")

        lines.append("# HELP push_relay_dispatches_total Total push dispatch attempts processed.")
        lines.append("# TYPE push_relay_dispatches_total counter")
        lines.append("push_relay_dispatches_total \(snapshot.totals.dispatches)")

        lines.append("# HELP push_relay_dispatches_by_outcome_total Push dispatch attempts partitioned by outcome.")
        lines.append("# TYPE push_relay_dispatches_by_outcome_total counter")
        lines.append("push_relay_dispatches_by_outcome_total{outcome=\"delivered\"} \(snapshot.totals.delivered)")
        lines.append("push_relay_dispatches_by_outcome_total{outcome=\"unregistered\"} \(snapshot.totals.unregistered)")
        lines.append("push_relay_dispatches_by_outcome_total{outcome=\"rate_limited\"} \(snapshot.totals.rateLimited)")
        lines.append("push_relay_dispatches_by_outcome_total{outcome=\"validation_rejected\"} \(snapshot.totals.validationRejected)")
        lines.append("push_relay_dispatches_by_outcome_total{outcome=\"upstream_failed\"} \(snapshot.totals.upstreamFailed)")
        lines.append("push_relay_dispatches_by_outcome_total{outcome=\"unsupported\"} \(snapshot.totals.unsupported)")

        lines.append("# HELP push_relay_rate_limited_total Requests rejected by rate limiters.")
        lines.append("# TYPE push_relay_rate_limited_total counter")
        lines.append("push_relay_rate_limited_total{scope=\"ip\"} \(snapshot.totals.ipRateLimited)")
        lines.append("push_relay_rate_limited_total{scope=\"token\"} \(snapshot.totals.tokenRateLimited)")

        let transportOrder = ["apns", "apns-voip", "apns-fileprovider", "fcm"]
        lines.append("# HELP push_relay_transport_enabled Whether each push transport is configured and enabled (1 = enabled, 0 = disabled).")
        lines.append("# TYPE push_relay_transport_enabled gauge")
        for transport in transportOrder {
            let enabled = (snapshot.transports[transport]?.enabled == true) ? 1 : 0
            lines.append("push_relay_transport_enabled{transport=\"\(escapeLabel(transport))\"} \(enabled)")
        }

        lines.append("# HELP push_relay_transport_dispatches_total Push dispatches by transport and outcome.")
        lines.append("# TYPE push_relay_transport_dispatches_total counter")
        for transport in transportOrder {
            let m = snapshot.transports[transport] ?? TransportMetrics(enabled: false, total: 0, delivered: 0, unregistered: 0, failed: 0)
            let t = escapeLabel(transport)
            lines.append("push_relay_transport_dispatches_total{transport=\"\(t)\",outcome=\"delivered\"} \(m.delivered)")
            lines.append("push_relay_transport_dispatches_total{transport=\"\(t)\",outcome=\"unregistered\"} \(m.unregistered)")
            lines.append("push_relay_transport_dispatches_total{transport=\"\(t)\",outcome=\"failed\"} \(m.failed)")
        }

        lines.append("# HELP push_relay_kind_dispatches_total Push dispatches by notification kind.")
        lines.append("# TYPE push_relay_kind_dispatches_total counter")
        for kind in ["alert", "background", "voip", "fileprovider"] {
            lines.append("push_relay_kind_dispatches_total{kind=\"\(kind)\"} \(snapshot.byKind[kind, default: 0])")
        }

        lines.append("# HELP push_relay_environment_dispatches_total Push dispatches by target APNs environment.")
        lines.append("# TYPE push_relay_environment_dispatches_total counter")
        for env in ["production", "sandbox"] {
            lines.append("push_relay_environment_dispatches_total{environment=\"\(env)\"} \(snapshot.byEnvironment[env, default: 0])")
        }

        if !snapshot.byTopic.isEmpty {
            lines.append("# HELP push_relay_topic_dispatches_total APNs dispatches by allowlisted topic (unknown topics grouped under 'disallowed').")
            lines.append("# TYPE push_relay_topic_dispatches_total counter")
            for topic in snapshot.byTopic.keys.sorted() {
                guard let m = snapshot.byTopic[topic] else { continue }
                let escaped = escapeLabel(topic)
                lines.append("push_relay_topic_dispatches_total{topic=\"\(escaped)\",outcome=\"delivered\"} \(m.delivered)")
                lines.append("push_relay_topic_dispatches_total{topic=\"\(escaped)\",outcome=\"unregistered\"} \(m.unregistered)")
                lines.append("push_relay_topic_dispatches_total{topic=\"\(escaped)\",outcome=\"failed\"} \(m.failed)")
            }
        }

        if !snapshot.reasons.isEmpty {
            lines.append("# HELP push_relay_reasons_total Non-success dispatch and rate-limit reason counts.")
            lines.append("# TYPE push_relay_reasons_total counter")
            for reason in snapshot.reasons.keys.sorted() {
                guard let count = snapshot.reasons[reason] else { continue }
                lines.append("push_relay_reasons_total{reason=\"\(escapeLabel(reason))\"} \(count)")
            }
        }

        lines.append("# HELP push_relay_apns_duration_seconds Upstream APNs request latency in seconds.")
        lines.append("# TYPE push_relay_apns_duration_seconds histogram")
        for (bound, cumulative) in zip(latencyHistogram.boundsSeconds, latencyHistogram.cumulativeCounts) {
            lines.append("push_relay_apns_duration_seconds_bucket{le=\"\(formatBound(bound))\"} \(cumulative)")
        }
        lines.append("push_relay_apns_duration_seconds_bucket{le=\"+Inf\"} \(latencyHistogram.count)")
        lines.append("push_relay_apns_duration_seconds_sum \(formatDouble(latencyHistogram.sumSeconds))")
        lines.append("push_relay_apns_duration_seconds_count \(latencyHistogram.count)")

        lines.append("# HELP push_relay_rate_limiter_buckets Currently active in-memory rate-limiter buckets.")
        lines.append("# TYPE push_relay_rate_limiter_buckets gauge")
        lines.append("push_relay_rate_limiter_buckets{scope=\"ip\"} \(snapshot.rateLimiter.activeIPBuckets)")
        lines.append("push_relay_rate_limiter_buckets{scope=\"token\"} \(snapshot.rateLimiter.activeTokenBuckets)")

        return lines.joined(separator: "\n") + "\n"
    }

    private static func escapeLabel(_ raw: String) -> String {
        var result = ""
        result.reserveCapacity(raw.count)
        for ch in raw {
            switch ch {
            case "\\": result.append("\\\\")
            case "\"": result.append("\\\"")
            case "\n": result.append("\\n")
            default: result.append(ch)
            }
        }
        return result
    }

    private static func formatBound(_ value: Double) -> String {
        if value.rounded() == value {
            return String(Int(value))
        }
        return String(value)
    }

    private static func formatDouble(_ value: Double) -> String {
        String(format: "%.6f", value)
    }
}
