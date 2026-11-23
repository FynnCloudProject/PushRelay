import Crypto
import Foundation
import Vapor

public final class AdminAuthService: Sendable {
    public let config: AdminConfig
    private let signingKey: SymmetricKey
    private let passwordDigest: Data
    private let loginLimiter: SlidingWindowRateLimiter
    private let now: @Sendable () -> Date

    public init(
        config: AdminConfig,
        signingKey: SymmetricKey = SymmetricKey(size: .bits256),
        loginLimiter: SlidingWindowRateLimiter? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.config = config
        self.signingKey = signingKey
        self.passwordDigest = Data(SHA256.hash(data: Data(config.password.utf8)))
        self.loginLimiter = loginLimiter ?? SlidingWindowRateLimiter(windowSeconds: 300, maxTrackedKeys: 10_000, now: now)
        self.now = now
    }

    public var cookieName: String {
        config.secureCookie ? "__Host-push_admin" : "push_admin"
    }

    public func verifyPassword(_ candidate: String) -> Bool {
        let candidateDigest = Data(SHA256.hash(data: Data(candidate.utf8)))
        return Self.constantTimeEquals(candidateDigest, passwordDigest)
    }

    public func verifyBearer(_ req: Request) -> Bool {
        guard let token = req.headers.bearerAuthorization?.token else { return false }
        return verifyPassword(token)
    }

    public func allowLoginAttempt(clientIP: String) async -> Bool {
        await loginLimiter.allow(rawKey: "admin-login:\(clientIP)", limit: config.loginRateLimitPer5Min)
    }

    public func createSessionToken() -> String {
        let issued = Int(now().timeIntervalSince1970)
        let expires = issued + config.sessionTTLSeconds
        let nonce = Self.randomHex(byteCount: 16)
        let payload = "s1|\(issued)|\(expires)|\(nonce)"
        let signature = sign(payload)
        return "\(Self.base64URLEncode(Data(payload.utf8))).\(Self.base64URLEncode(signature))"
    }

    public func verifySessionToken(_ token: String?) -> Bool {
        guard let token, !token.isEmpty else { return false }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let payloadData = Self.base64URLDecode(String(parts[0])),
              let providedSig = Self.base64URLDecode(String(parts[1])),
              let payload = String(data: payloadData, encoding: .utf8)
        else {
            return false
        }

        let expectedSig = sign(payload)
        guard Self.constantTimeEquals(providedSig, expectedSig) else { return false }

        let fields = payload.split(separator: "|", omittingEmptySubsequences: false)
        guard fields.count == 4,
              fields[0] == "s1",
              let issued = Int(fields[1]),
              let expires = Int(fields[2])
        else {
            return false
        }

        let current = Int(now().timeIntervalSince1970)
        return current >= issued - 5 && current < expires
    }

    public func makeSessionCookie(token: String) -> HTTPCookies.Value {
        HTTPCookies.Value(
            string: token,
            expires: now().addingTimeInterval(TimeInterval(config.sessionTTLSeconds)),
            maxAge: config.sessionTTLSeconds,
            domain: nil,
            path: "/",
            isSecure: config.secureCookie,
            isHTTPOnly: true,
            sameSite: .lax
        )
    }

    public func makeExpiredCookie() -> HTTPCookies.Value {
        HTTPCookies.Value(
            string: "",
            expires: Date(timeIntervalSince1970: 0),
            maxAge: 0,
            domain: nil,
            path: "/",
            isSecure: config.secureCookie,
            isHTTPOnly: true,
            sameSite: .lax
        )
    }

    public func createCSRFToken(binding: String) -> String {
        let issued = Int(now().timeIntervalSince1970)
        let nonce = Self.randomHex(byteCount: 12)
        let payload = "c1|\(issued)|\(nonce)"
        let signature = sign("\(payload)|\(binding)")
        return "\(Self.base64URLEncode(Data(payload.utf8))).\(Self.base64URLEncode(signature))"
    }

    public func verifyCSRFToken(_ token: String?, binding: String, maxAgeSeconds: Int = 3_600) -> Bool {
        guard let token, !token.isEmpty else { return false }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let payloadData = Self.base64URLDecode(String(parts[0])),
              let providedSig = Self.base64URLDecode(String(parts[1])),
              let payload = String(data: payloadData, encoding: .utf8)
        else {
            return false
        }

        let expectedSig = sign("\(payload)|\(binding)")
        guard Self.constantTimeEquals(providedSig, expectedSig) else { return false }

        let fields = payload.split(separator: "|", omittingEmptySubsequences: false)
        guard fields.count == 3,
              fields[0] == "c1",
              let issued = Int(fields[1])
        else {
            return false
        }

        let current = Int(now().timeIntervalSince1970)
        return current >= issued - 5 && (current - issued) <= maxAgeSeconds
    }

    public func generateCSPNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        var rng = SystemRandomNumberGenerator()
        for i in bytes.indices {
            bytes[i] = rng.next()
        }
        return Data(bytes).base64EncodedString()
    }

    private func sign(_ message: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: signingKey))
    }

    private static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for (a, b) in zip(lhs, rhs) {
            diff |= a ^ b
        }
        return diff == 0
    }

    private static func randomHex(byteCount: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        var rng = SystemRandomNumberGenerator()
        for i in bytes.indices {
            bytes[i] = rng.next()
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func base64URLDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }
}
