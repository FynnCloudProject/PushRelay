import Crypto
import Foundation

public actor SlidingWindowRateLimiter {
    private let windowSeconds: TimeInterval
    private let maxTrackedKeys: Int
    private let now: @Sendable () -> Date
    private var buckets: [Data: [TimeInterval]] = [:]

    public init(
        windowSeconds: TimeInterval = 60,
        maxTrackedKeys: Int = 50_000,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.windowSeconds = windowSeconds
        self.maxTrackedKeys = maxTrackedKeys
        self.now = now
    }

    public func allow(rawKey: String, limit: Int, cost: Int = 1) -> Bool {
        guard limit > 0 else { return true }
        let effectiveCost = max(1, cost)
        let current = now().timeIntervalSince1970
        let cutoff = current - windowSeconds
        // Store SHA-256 hashes so raw client IPs and device tokens are never retained in memory.
        let keyHash = Data(SHA256.hash(data: Data(rawKey.utf8)))

        if buckets.count >= maxTrackedKeys && buckets[keyHash] == nil {
            prune(cutoff: cutoff)
            if buckets.count >= maxTrackedKeys {
                buckets.removeAll(keepingCapacity: true)
            }
        }

        var timestamps = buckets[keyHash] ?? []
        timestamps.removeAll { $0 <= cutoff }

        guard timestamps.count + effectiveCost <= limit else {
            buckets[keyHash] = timestamps
            return false
        }

        timestamps.append(contentsOf: repeatElement(current, count: effectiveCost))
        buckets[keyHash] = timestamps
        return true
    }

    public func activeKeyCount() -> Int {
        let cutoff = now().timeIntervalSince1970 - windowSeconds
        prune(cutoff: cutoff)
        return buckets.count
    }

    private func prune(cutoff: TimeInterval) {
        for (key, var timestamps) in buckets {
            timestamps.removeAll { $0 <= cutoff }
            buckets[key] = timestamps.isEmpty ? nil : timestamps
        }
    }
}
