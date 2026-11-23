import Crypto
import Foundation
import Leaf
import Vapor

public struct AdminController: RouteCollection, Sendable {
    private let auth: AdminAuthService
    private let cssBody: String
    private let cssHref: String

    public init(auth: AdminAuthService, cssBody: String) {
        self.auth = auth
        self.cssBody = cssBody
        let hash = SHA256.hash(data: Data(cssBody.utf8))
            .prefix(6)
            .map { String(format: "%02x", $0) }
            .joined()
        self.cssHref = "/admin/assets/admin.css?v=\(hash)"
    }

    public func boot(routes: any RoutesBuilder) throws {
        let admin = routes.grouped("admin")
        admin.get(use: dashboard)
        admin.get("login", use: loginPage)
        admin.post("login", use: loginSubmit)
        admin.post("logout", use: logout)
        admin.get("metrics.json", use: metricsJSON)
        admin.get("metrics", use: metricsPrometheus)
        admin.get("assets", "admin.css", use: stylesheet)
    }

    @Sendable
    func stylesheet(req: Request) -> Response {
        if let blocked = enforceFetchMetadata(req) { return blocked }
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: "text/css; charset=utf-8")
        headers.replaceOrAdd(name: .cacheControl, value: "no-cache")
        applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
        return Response(status: .ok, headers: headers, body: .init(string: cssBody))
    }

    @Sendable
    func loginPage(req: Request) async throws -> Response {
        if let blocked = enforceFetchMetadata(req) { return blocked }

        if let session = req.cookies[auth.cookieName]?.string, auth.verifySessionToken(session) {
            return makeRedirect(to: "/admin")
        }

        let statusParam = req.query[String.self, at: "error"]
        let errorMessage: String? = switch statusParam {
        case "invalid": "Invalid password."
        case "csrf": "Your sign-in form expired. Please try again."
        case "rate": "Too many failed attempts. Please wait a few minutes."
        default: nil
        }

        return try await renderLogin(req: req, status: .ok, errorMessage: errorMessage)
    }

    private struct LoginForm: Content {
        let password: String?
        let _csrf: String?
    }

    @Sendable
    func loginSubmit(req: Request) async throws -> Response {
        if let blocked = enforceFetchMetadata(req) { return blocked }

        let form = (try? req.content.decode(LoginForm.self)) ?? LoginForm(password: nil, _csrf: nil)
        guard auth.verifyCSRFToken(form._csrf, binding: "login") else {
            return try await renderLogin(
                req: req,
                status: .forbidden,
                errorMessage: "Your sign-in form expired. Please try again."
            )
        }

        let dispatcher = req.application.pushDispatcher
        let clientIP = req.clientIP(trustProxyHeaders: dispatcher.config.trustProxyHeaders)
        guard await auth.allowLoginAttempt(clientIP: clientIP) else {
            return try await renderLogin(
                req: req,
                status: .tooManyRequests,
                errorMessage: "Too many failed attempts. Please wait a few minutes."
            )
        }

        guard let password = form.password, !password.isEmpty, auth.verifyPassword(password) else {
            return try await renderLogin(
                req: req,
                status: .unauthorized,
                errorMessage: "Invalid password."
            )
        }

        let token = auth.createSessionToken()
        let response = makeRedirect(to: "/admin")
        response.cookies[auth.cookieName] = auth.makeSessionCookie(token: token)
        return response
    }

    private struct LogoutForm: Content {
        let _csrf: String?
    }

    @Sendable
    func logout(req: Request) async throws -> Response {
        if let blocked = enforceFetchMetadata(req) { return blocked }

        let session = req.cookies[auth.cookieName]?.string
        let form = (try? req.content.decode(LogoutForm.self)) ?? LogoutForm(_csrf: nil)
        if let session, auth.verifySessionToken(session) {
            guard auth.verifyCSRFToken(form._csrf, binding: session) else {
                var headers = HTTPHeaders()
                applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
                return Response(status: .forbidden, headers: headers, body: .init(string: "Invalid CSRF token."))
            }
        }

        let response = makeRedirect(to: "/admin/login")
        response.cookies[auth.cookieName] = auth.makeExpiredCookie()
        response.headers.replaceOrAdd(name: "Clear-Site-Data", value: #""cookies", "storage", "cache""#)
        return response
    }

    @Sendable
    func dashboard(req: Request) async throws -> Response {
        if let blocked = enforceFetchMetadata(req) { return blocked }

        guard let session = req.cookies[auth.cookieName]?.string, auth.verifySessionToken(session) else {
            return makeRedirect(to: "/admin/login")
        }

        let snapshot = await req.application.pushDispatcher.metricsSnapshot()
        let nonce = auth.generateCSPNonce()
        let csrfToken = auth.createCSRFToken(binding: session)
        let context = DashboardViewContext(
            cssHref: cssHref,
            cspNonce: nonce,
            csrfToken: csrfToken,
            snapshot: snapshot
        )

        let view = try await req.view.render("admin-dashboard", context)
        return makeHTMLResponse(status: .ok, view: view, cspNonce: nonce)
    }

    @Sendable
    func metricsJSON(req: Request) async throws -> Response {
        if let blocked = enforceFetchMetadata(req) { return blocked }

        let hasCookie = auth.verifySessionToken(req.cookies[auth.cookieName]?.string)
        let hasBearer = auth.verifyBearer(req)
        guard hasCookie || hasBearer else {
            var headers = HTTPHeaders()
            headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
            return Response(status: .unauthorized, headers: headers)
        }

        let snapshot = await req.application.pushDispatcher.metricsSnapshot()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: "application/json; charset=utf-8")
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
        return Response(status: .ok, headers: headers, body: .init(data: try encoder.encode(snapshot)))
    }

    @Sendable
    func metricsPrometheus(req: Request) async throws -> Response {
        if let blocked = enforceFetchMetadata(req) { return blocked }

        let hasCookie = auth.verifySessionToken(req.cookies[auth.cookieName]?.string)
        let hasBearer = auth.verifyBearer(req)
        guard hasCookie || hasBearer else {
            var headers = HTTPHeaders()
            headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
            return Response(status: .unauthorized, headers: headers)
        }

        let text = await req.application.pushDispatcher.prometheusMetricsText()
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: PrometheusMetricsFormatter.contentType)
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
        return Response(status: .ok, headers: headers, body: .init(string: text))
    }

    private struct LoginViewContext: Encodable {
        let cssHref: String
        let cspNonce: String
        let csrfToken: String
        let errorMessage: String?
    }

    private struct TransportRowView: Encodable {
        let label: String
        let platform: String
        let enabled: Bool
        let statusLabel: String
        let total: Int
        let delivered: Int
        let unregistered: Int
        let failed: Int
    }

    private struct TopicRowView: Encodable {
        let topic: String
        let total: Int
        let delivered: Int
        let unregistered: Int
        let failed: Int
    }

    private struct KeyCountView: Encodable {
        let name: String
        let count: Int
    }

    private struct ChartBarView: Encodable {
        let label: String
        let delivered: Int
        let failed: Int
        let total: Int
        let barX: Int
        let deliveredY: Int
        let deliveredHeight: Int
        let failedY: Int
        let failedHeight: Int
    }

    private struct LatencyView: Encodable {
        let samples: Int
        let avgMs: String
        let p50Ms: String
        let p95Ms: String
        let maxMs: String
    }

    private struct DashboardViewContext: Encodable {
        let cssHref: String
        let cspNonce: String
        let csrfToken: String
        let version: String
        let uptimeFormatted: String
        let healthState: String
        let healthTitle: String
        let healthDescription: String
        let successRate: String
        let totals: MetricsTotals
        let throughput: ThroughputSummary
        let latency: LatencyView
        let transports: [TransportRowView]
        let byKind: [KeyCountView]
        let byEnvironment: [KeyCountView]
        let byTopic: [TopicRowView]
        let topReasons: [KeyCountView]
        let timeline: [ChartBarView]
        let timelinePeak: Int
        let activeTimeline: [ChartBarView]
        let rateLimiter: RateLimiterMetrics
        let config: SafeConfigSummary
        let hasTopics: Bool
        let hasReasons: Bool
        let hasActiveTimeline: Bool

        init(cssHref: String, cspNonce: String, csrfToken: String, snapshot: MetricsSnapshot) {
            self.cssHref = cssHref
            self.cspNonce = cspNonce
            self.csrfToken = csrfToken
            self.version = snapshot.version
            self.uptimeFormatted = Self.formatUptime(snapshot.uptimeSeconds)
            self.totals = snapshot.totals
            self.throughput = snapshot.throughput
            self.rateLimiter = snapshot.rateLimiter
            self.config = snapshot.config

            if snapshot.totals.dispatches > 0 {
                let pct = (Double(snapshot.totals.delivered) / Double(snapshot.totals.dispatches)) * 100.0
                self.successRate = String(format: "%.1f%%", pct)
            } else {
                self.successRate = "—"
            }

            self.latency = LatencyView(
                samples: snapshot.latencyMs.samples,
                avgMs: Self.formatMs(snapshot.latencyMs.avg),
                p50Ms: Self.formatMs(snapshot.latencyMs.p50),
                p95Ms: Self.formatMs(snapshot.latencyMs.p95),
                maxMs: Self.formatMs(snapshot.latencyMs.max)
            )

            let transportSpecs: [(id: String, label: String, platform: String)] = [
                ("apns", "APNs", "iOS & macOS"),
                ("apns-voip", "APNs VoIP", "iOS PushKit"),
                ("apns-fileprovider", "APNs FileProvider", "iOS & macOS PushKit"),
                ("fcm", "FCM", "Android"),
            ]
            let rows = transportSpecs.map { spec -> TransportRowView in
                let m = snapshot.transports[spec.id] ?? TransportMetrics(enabled: false, total: 0, delivered: 0, unregistered: 0, failed: 0)
                return TransportRowView(
                    label: spec.label,
                    platform: spec.platform,
                    enabled: m.enabled,
                    statusLabel: m.enabled ? "Active" : "Disabled",
                    total: m.total,
                    delivered: m.delivered,
                    unregistered: m.unregistered,
                    failed: m.failed
                )
            }
            self.transports = rows

            let activeCount = rows.filter(\.enabled).count
            if activeCount == 0 {
                self.healthState = "warning"
                self.healthTitle = "No transports configured"
                self.healthDescription = "0 of \(rows.count) transports active"
            } else if snapshot.totals.upstreamFailed > 0 {
                self.healthState = "warning"
                self.healthTitle = "Upstream errors"
                self.healthDescription = "\(snapshot.totals.upstreamFailed) upstream 5xx · \(activeCount) of \(rows.count) transports active"
            } else {
                self.healthState = "healthy"
                self.healthTitle = "Operational"
                self.healthDescription = "\(activeCount) of \(rows.count) transports active"
            }

            self.byKind = ["alert", "background", "voip", "fileprovider"].map {
                KeyCountView(name: $0, count: snapshot.byKind[$0, default: 0])
            }
            self.byEnvironment = ["production", "sandbox"].map {
                KeyCountView(name: $0, count: snapshot.byEnvironment[$0, default: 0])
            }
            self.byTopic = snapshot.byTopic
                .map { TopicRowView(topic: $0.key, total: $0.value.total, delivered: $0.value.delivered, unregistered: $0.value.unregistered, failed: $0.value.failed) }
                .sorted { $0.total != $1.total ? $0.total > $1.total : $0.topic < $1.topic }

            self.topReasons = Array(
                snapshot.reasons
                    .map { KeyCountView(name: $0.key, count: $0.value) }
                    .sorted { $0.count != $1.count ? $0.count > $1.count : $0.name < $1.name }
                    .prefix(12)
            )

            let peak = snapshot.timeline.map { $0.delivered + $0.failed }.max() ?? 0
            let scalePeak = max(1, peak)
            let plotHeight = 120
            let baselineY = 8 + plotHeight
            let bars: [ChartBarView] = snapshot.timeline.enumerated().map { index, item in
                let total = item.delivered + item.failed
                let delH = item.delivered > 0 ? max(2, Int((Double(item.delivered) / Double(scalePeak)) * Double(plotHeight))) : 0
                let failH = item.failed > 0 ? max(2, Int((Double(item.failed) / Double(scalePeak)) * Double(plotHeight))) : 0
                let clampedDelH = min(plotHeight, delH)
                let clampedFailH = min(max(0, plotHeight - clampedDelH), failH)
                let delY = baselineY - clampedDelH
                let failY = delY - clampedFailH
                return ChartBarView(
                    label: Self.shortTime(from: item.minute),
                    delivered: item.delivered,
                    failed: item.failed,
                    total: total,
                    barX: index * 10 + 1,
                    deliveredY: delY,
                    deliveredHeight: clampedDelH,
                    failedY: failY,
                    failedHeight: clampedFailH
                )
            }
            self.timeline = bars
            self.timelinePeak = peak
            self.activeTimeline = bars.filter { $0.total > 0 }.reversed()
            self.hasTopics = !self.byTopic.isEmpty
            self.hasReasons = !self.topReasons.isEmpty
            self.hasActiveTimeline = !self.activeTimeline.isEmpty
        }

        private static func formatMs(_ ms: Double?) -> String {
            guard let ms else { return "—" }
            return String(format: "%.1f ms", ms)
        }

        private static func shortTime(from isoMinute: String) -> String {
            guard let tIndex = isoMinute.firstIndex(of: "T") else { return isoMinute }
            let afterT = isoMinute[isoMinute.index(after: tIndex)...]
            return String(afterT.prefix(5))
        }

        private static func formatUptime(_ seconds: Int) -> String {
            let days = seconds / 86_400
            let hours = (seconds % 86_400) / 3_600
            let minutes = (seconds % 3_600) / 60
            let secs = seconds % 60
            if days > 0 { return "\(days)d \(hours)h \(minutes)m" }
            if hours > 0 { return "\(hours)h \(minutes)m \(secs)s" }
            if minutes > 0 { return "\(minutes)m \(secs)s" }
            return "\(secs)s"
        }
    }

    private func renderLogin(req: Request, status: HTTPResponseStatus, errorMessage: String?) async throws -> Response {
        let nonce = auth.generateCSPNonce()
        let csrf = auth.createCSRFToken(binding: "login")
        let context = LoginViewContext(
            cssHref: cssHref,
            cspNonce: nonce,
            csrfToken: csrf,
            errorMessage: errorMessage
        )
        let view = try await req.view.render("admin-login", context)
        return makeHTMLResponse(status: status, view: view, cspNonce: nonce)
    }

    private func makeHTMLResponse(status: HTTPResponseStatus, view: View, cspNonce: String) -> Response {
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: "text/html; charset=utf-8")
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        let csp = [
            "default-src 'none'",
            "style-src 'self'",
            "img-src 'self'",
            "connect-src 'self'",
            "script-src 'nonce-\(cspNonce)' 'strict-dynamic' 'report-sample'",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "require-trusted-types-for 'script'",
        ].joined(separator: "; ")
        applySecurityHeaders(&headers, csp: csp)
        return Response(status: status, headers: headers, body: .init(buffer: view.data))
    }

    private func makeRedirect(to location: String) -> Response {
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .location, value: location)
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
        return Response(status: .seeOther, headers: headers)
    }

    private func enforceFetchMetadata(_ req: Request) -> Response? {
        guard let site = req.headers.first(name: "Sec-Fetch-Site")?.lowercased() else {
            return nil
        }
        if site == "same-origin" || site == "none" {
            return nil
        }

        let mode = req.headers.first(name: "Sec-Fetch-Mode")?.lowercased() ?? ""
        let dest = req.headers.first(name: "Sec-Fetch-Dest")?.lowercased() ?? ""
        if site == "cross-site",
           mode == "navigate",
           req.method == .GET,
           dest != "object",
           dest != "embed",
           dest != "iframe"
        {
            return nil
        }

        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        applySecurityHeaders(&headers, csp: "default-src 'none'; frame-ancestors 'none'")
        return Response(status: .forbidden, headers: headers, body: .init(string: "Forbidden"))
    }

    private func applySecurityHeaders(_ headers: inout HTTPHeaders, csp: String) {
        headers.replaceOrAdd(name: "Content-Security-Policy", value: csp)
        headers.replaceOrAdd(name: "X-Frame-Options", value: "DENY")
        headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        headers.replaceOrAdd(name: "Referrer-Policy", value: "strict-origin-when-cross-origin")
        headers.replaceOrAdd(name: "Cross-Origin-Opener-Policy", value: "same-origin")
        headers.replaceOrAdd(name: "Cross-Origin-Resource-Policy", value: "same-origin")
        headers.replaceOrAdd(
            name: "Permissions-Policy",
            value: "camera=(), geolocation=(), microphone=(), focus-without-user-activation=()"
        )
        headers.replaceOrAdd(name: .vary, value: "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site")
        if auth.config.secureCookie {
            headers.replaceOrAdd(name: "Strict-Transport-Security", value: "max-age=300; includeSubDomains")
        }
    }
}
