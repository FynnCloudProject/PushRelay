import APNS
import APNSCore
import Crypto
import Foundation
import Leaf
import Vapor
import VaporAPNS

private struct PushDispatcherKey: StorageKey {
    typealias Value = PushDispatcher
}

extension Application {
    public var pushDispatcher: PushDispatcher {
        get {
            guard let dispatcher = storage[PushDispatcherKey.self] else {
                fatalError("PushDispatcher not configured on Application.")
            }
            return dispatcher
        }
        set {
            storage[PushDispatcherKey.self] = newValue
        }
    }
}

public func configure(
    _ app: Application,
    config: RelayConfig? = nil,
    productionAPNS: (any APNSClientProtocol)? = nil,
    sandboxAPNS: (any APNSClientProtocol)? = nil,
    now: @escaping @Sendable () -> Date = Date.init
) async throws {
    app.routes.defaultMaxBodySize = "768kb"

    // Omit Vapor's default RouteLoggingMiddleware so client IPs and request paths are not logged.
    app.middleware = Middlewares()
    app.middleware.use(ErrorMiddleware.default(environment: app.environment))

    let resolvedConfig = try config ?? RelayConfig.load(isProduction: app.environment == .production)

    let apnsService: APNSService?
    if let apnsConfig = resolvedConfig.apns {
        let resolvedProduction: any APNSClientProtocol
        let resolvedSandbox: (any APNSClientProtocol)?

        if let productionAPNS {
            resolvedProduction = productionAPNS
            resolvedSandbox = apnsConfig.allowSandbox ? (sandboxAPNS ?? productionAPNS) : nil
        } else {
            let auth: APNSClientConfiguration.AuthenticationMethod = .jwt(
                privateKey: try P256.Signing.PrivateKey(pemRepresentation: apnsConfig.privateKeyPEM),
                keyIdentifier: apnsConfig.keyID,
                teamIdentifier: apnsConfig.teamID
            )
            await app.apns.containers.use(
                APNSClientConfiguration(authenticationMethod: auth, environment: .production),
                eventLoopGroupProvider: .shared(app.eventLoopGroup),
                responseDecoder: JSONDecoder(),
                requestEncoder: JSONEncoder(),
                as: .production
            )
            resolvedProduction = await app.apns.client(.production)

            if apnsConfig.allowSandbox {
                await app.apns.containers.use(
                    APNSClientConfiguration(authenticationMethod: auth, environment: .development),
                    eventLoopGroupProvider: .shared(app.eventLoopGroup),
                    responseDecoder: JSONDecoder(),
                    requestEncoder: JSONEncoder(),
                    as: .development
                )
                resolvedSandbox = await app.apns.client(.development)
            } else {
                resolvedSandbox = nil
            }
        }

        apnsService = APNSService(
            config: apnsConfig,
            productionClient: resolvedProduction,
            sandboxClient: resolvedSandbox,
            now: now
        )
    } else {
        apnsService = nil
        app.logger.warning("APNs is not configured (set APNS_TEAM_ID, APNS_KEY_ID, and APNS_PRIVATE_KEY*).")
    }

    let metrics = MetricsStore(
        allowedTopics: resolvedConfig.apns?.allowedTopics ?? [],
        allowedVoIPTopics: resolvedConfig.apns?.allowedVoIPTopics ?? [],
        allowedFileProviderTopics: resolvedConfig.apns?.allowedFileProviderTopics ?? [],
        now: now
    )
    app.pushDispatcher = PushDispatcher(config: resolvedConfig, apnsService: apnsService, metrics: metrics)

    var adminController: AdminController?
    if let adminConfig = resolvedConfig.admin {
        let resourcesDir = resolveResourcesDirectory(app)
        app.leaf.configuration.rootDirectory = resourcesDir.appendingPathComponent("Views").path
        app.views.use(.leaf)

        let cssURL = resourcesDir.appendingPathComponent("Public/admin.css")
        let cssBody = (try? String(contentsOf: cssURL, encoding: .utf8)) ?? ""
        let auth = AdminAuthService(config: adminConfig, now: now)
        adminController = AdminController(auth: auth, cssBody: cssBody)
    }

    try routes(app, adminController: adminController)
}

private func resolveResourcesDirectory(_ app: Application) -> URL {
    let fm = FileManager.default
    let workingResources = URL(fileURLWithPath: app.directory.workingDirectory)
        .appendingPathComponent("Resources", isDirectory: true)
    if fm.fileExists(atPath: workingResources.appendingPathComponent("Views").path) {
        return workingResources
    }
    return URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Resources", isDirectory: true)
}
