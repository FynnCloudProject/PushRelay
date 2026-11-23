import Crypto
import Foundation
import Vapor

public struct APNSConfig: Sendable {
    public let teamID: String
    public let keyID: String
    public let privateKeyPEM: String
    public let allowedTopics: Set<String>
    public let allowedVoIPTopics: Set<String>
    public let allowedFileProviderTopics: Set<String>
    public let allowSandbox: Bool

    public init(
        teamID: String,
        keyID: String,
        privateKeyPEM: String,
        allowedTopics: Set<String>,
        allowedVoIPTopics: Set<String>,
        allowedFileProviderTopics: Set<String> = [],
        allowSandbox: Bool = true
    ) throws {
        let trimmedTeam = teamID.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedKey = keyID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedTeam.isEmpty else {
            throw RelayConfigError.invalidConfiguration("APNS_TEAM_ID must not be empty.")
        }
        guard !trimmedKey.isEmpty else {
            throw RelayConfigError.invalidConfiguration("APNS_KEY_ID must not be empty.")
        }
        let normalizedPEM = Self.normalizePEM(privateKeyPEM)
        do {
            _ = try P256.Signing.PrivateKey(pemRepresentation: normalizedPEM)
        } catch {
            throw RelayConfigError.invalidConfiguration("APNs private key is not a valid P-256 PEM (.p8): \(error)")
        }

        let cleanTopics = Set(allowedTopics.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })
        let cleanVoIP = Set(allowedVoIPTopics.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })
        let cleanFileProvider = Set(allowedFileProviderTopics.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })

        guard !cleanTopics.isEmpty || !cleanVoIP.isEmpty || !cleanFileProvider.isEmpty else {
            throw RelayConfigError.invalidConfiguration(
                "Configure at least one topic in APNS_ALLOWED_TOPICS, APNS_ALLOWED_VOIP_TOPICS, or APNS_ALLOWED_FILEPROVIDER_TOPICS."
            )
        }
        for topic in cleanVoIP where !topic.hasSuffix(".voip") {
            throw RelayConfigError.invalidConfiguration(
                "APNS_ALLOWED_VOIP_TOPICS entry '\(topic)' must end with '.voip'."
            )
        }
        for topic in cleanFileProvider where !topic.hasSuffix(".pushkit.fileprovider") {
            throw RelayConfigError.invalidConfiguration(
                "APNS_ALLOWED_FILEPROVIDER_TOPICS entry '\(topic)' must end with '.pushkit.fileprovider'."
            )
        }
        for topic in cleanTopics where topic.hasSuffix(".voip") || topic.hasSuffix(".pushkit.fileprovider") {
            throw RelayConfigError.invalidConfiguration(
                "APNS_ALLOWED_TOPICS entry '\(topic)' uses a PushKit suffix; put VoIP topics in APNS_ALLOWED_VOIP_TOPICS and FileProvider topics in APNS_ALLOWED_FILEPROVIDER_TOPICS."
            )
        }

        self.teamID = trimmedTeam
        self.keyID = trimmedKey
        self.privateKeyPEM = normalizedPEM
        self.allowedTopics = cleanTopics
        self.allowedVoIPTopics = cleanVoIP
        self.allowedFileProviderTopics = cleanFileProvider
        self.allowSandbox = allowSandbox
    }

    static func normalizePEM(_ raw: String) -> String {
        raw.replacingOccurrences(of: "\\n", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

public struct AdminConfig: Sendable {
    public static let minimumPasswordLength = 12

    public let password: String
    public let secureCookie: Bool
    public let sessionTTLSeconds: Int
    public let loginRateLimitPer5Min: Int

    public init(
        password: String,
        secureCookie: Bool = true,
        sessionTTLSeconds: Int = 12 * 3_600,
        loginRateLimitPer5Min: Int = 10
    ) throws {
        let trimmed = password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.utf8.count >= Self.minimumPasswordLength else {
            throw RelayConfigError.invalidConfiguration(
                "ADMIN_PASSWORD must be at least \(Self.minimumPasswordLength) characters."
            )
        }
        self.password = trimmed
        self.secureCookie = secureCookie
        self.sessionTTLSeconds = max(300, min(sessionTTLSeconds, 7 * 24 * 3_600))
        self.loginRateLimitPer5Min = max(1, loginRateLimitPer5Min)
    }
}

public struct RelayConfig: Sendable {
    public static let serviceVersion = "1.0.0"

    public let apns: APNSConfig?
    public let admin: AdminConfig?
    public let metricsBearerToken: String?
    public let sharedSecret: String?
    public let trustProxyHeaders: Bool
    public let rateLimitIPPerMinute: Int
    public let rateLimitTokenPerMinute: Int
    public let maxBatchSize: Int

    public init(
        apns: APNSConfig?,
        admin: AdminConfig? = nil,
        metricsBearerToken: String? = nil,
        sharedSecret: String? = nil,
        trustProxyHeaders: Bool = false,
        rateLimitIPPerMinute: Int = 600,
        rateLimitTokenPerMinute: Int = 120,
        maxBatchSize: Int = 100
    ) {
        self.apns = apns
        self.admin = admin
        let trimmedMetricsToken = metricsBearerToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.metricsBearerToken = (trimmedMetricsToken?.isEmpty == false) ? trimmedMetricsToken : nil
        self.sharedSecret = sharedSecret?.isEmpty == true ? nil : sharedSecret
        self.trustProxyHeaders = trustProxyHeaders
        self.rateLimitIPPerMinute = max(0, rateLimitIPPerMinute)
        self.rateLimitTokenPerMinute = max(0, rateLimitTokenPerMinute)
        self.maxBatchSize = max(1, min(maxBatchSize, 500))
    }

    public static func load(
        env: (String) -> String? = Environment.get,
        isProduction: Bool = true
    ) throws -> RelayConfig {
        let adminConfig: AdminConfig?
        if let rawAdminPassword = env("ADMIN_PASSWORD")?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawAdminPassword.isEmpty
        {
            adminConfig = try AdminConfig(
                password: rawAdminPassword,
                secureCookie: parseBool(env("ADMIN_COOKIE_SECURE"), default: isProduction),
                sessionTTLSeconds: env("ADMIN_SESSION_TTL_SECONDS").flatMap(Int.init) ?? (12 * 3_600),
                loginRateLimitPer5Min: env("ADMIN_LOGIN_RATE_LIMIT_PER_5M").flatMap(Int.init) ?? 10
            )
        } else {
            adminConfig = nil
        }

        return RelayConfig(
            apns: try loadAPNSConfig(env: env),
            admin: adminConfig,
            metricsBearerToken: env("METRICS_BEARER_TOKEN"),
            sharedSecret: env("RELAY_SHARED_SECRET")?.trimmingCharacters(in: .whitespacesAndNewlines),
            trustProxyHeaders: parseBool(env("TRUST_PROXY_HEADERS"), default: false),
            rateLimitIPPerMinute: env("RATE_LIMIT_IP_PER_MINUTE").flatMap(Int.init) ?? 600,
            rateLimitTokenPerMinute: env("RATE_LIMIT_TOKEN_PER_MINUTE").flatMap(Int.init) ?? 120,
            maxBatchSize: env("RELAY_MAX_BATCH_SIZE").flatMap(Int.init) ?? 100
        )
    }

    private static func loadAPNSConfig(env: (String) -> String?) throws -> APNSConfig? {
        let teamID = env("APNS_TEAM_ID")?.trimmingCharacters(in: .whitespacesAndNewlines)
        let keyID = env("APNS_KEY_ID")?.trimmingCharacters(in: .whitespacesAndNewlines)
        let keyInline = env("APNS_PRIVATE_KEY")?.trimmingCharacters(in: .whitespacesAndNewlines)
        let keyBase64 = env("APNS_PRIVATE_KEY_BASE64")?.trimmingCharacters(in: .whitespacesAndNewlines)
        let keyPath = env("APNS_PRIVATE_KEY_PATH")?.trimmingCharacters(in: .whitespacesAndNewlines)

        let anyProvided = [teamID, keyID, keyInline, keyBase64, keyPath].contains { !($0 ?? "").isEmpty }
        guard anyProvided else { return nil }

        let pem: String
        if let keyInline, !keyInline.isEmpty {
            pem = keyInline
        } else if let keyBase64, !keyBase64.isEmpty {
            guard let decoded = Data(base64Encoded: keyBase64),
                  let text = String(data: decoded, encoding: .utf8)
            else {
                throw RelayConfigError.invalidConfiguration("APNS_PRIVATE_KEY_BASE64 is not valid UTF-8 base64.")
            }
            pem = text
        } else if let keyPath, !keyPath.isEmpty {
            do {
                pem = try String(contentsOfFile: keyPath, encoding: .utf8)
            } catch {
                throw RelayConfigError.invalidConfiguration("Could not read APNS_PRIVATE_KEY_PATH '\(keyPath)': \(error)")
            }
        } else {
            throw RelayConfigError.invalidConfiguration(
                "APNs is partially configured: provide APNS_PRIVATE_KEY_PATH, APNS_PRIVATE_KEY, or APNS_PRIVATE_KEY_BASE64."
            )
        }

        return try APNSConfig(
            teamID: teamID ?? "",
            keyID: keyID ?? "",
            privateKeyPEM: pem,
            allowedTopics: parseCSV(env("APNS_ALLOWED_TOPICS")),
            allowedVoIPTopics: parseCSV(env("APNS_ALLOWED_VOIP_TOPICS")),
            allowedFileProviderTopics: parseCSV(env("APNS_ALLOWED_FILEPROVIDER_TOPICS")),
            allowSandbox: parseBool(env("APNS_ALLOW_SANDBOX"), default: true)
        )
    }

    private static func parseCSV(_ raw: String?) -> Set<String> {
        guard let raw else { return [] }
        return Set(
            raw.split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        )
    }

    private static func parseBool(_ raw: String?, default fallback: Bool) -> Bool {
        guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !raw.isEmpty else {
            return fallback
        }
        switch raw {
        case "1", "true", "yes", "on": return true
        case "0", "false", "no", "off": return false
        default: return fallback
        }
    }
}

public enum RelayConfigError: Error, CustomStringConvertible, Sendable {
    case invalidConfiguration(String)

    public var description: String {
        switch self {
        case .invalidConfiguration(let msg): return "RelayConfigError: \(msg)"
        }
    }
}
