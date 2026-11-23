// swift-tools-version:6.2
import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("ExistentialAny"),
]

let package = Package(
    name: "PushRelay",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.121.4"),
        .package(url: "https://github.com/vapor/leaf.git", from: "4.4.0"),
        .package(url: "https://github.com/vapor/apns.git", from: "5.0.0"),
        .package(url: "https://github.com/kylebrowning/APNSwift.git", from: "7.0.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
    ],
    targets: [
        .executableTarget(
            name: "PushRelay",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Leaf", package: "leaf"),
                .product(name: "VaporAPNS", package: "apns"),
                .product(name: "APNS", package: "APNSwift"),
                .product(name: "APNSCore", package: "APNSwift"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/PushRelay",
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "PushRelayTests",
            dependencies: [
                .target(name: "PushRelay"),
                .product(name: "APNSCore", package: "APNSwift"),
                .product(name: "VaporTesting", package: "vapor"),
            ],
            path: "Tests/PushRelayTests",
            swiftSettings: swiftSettings
        ),
    ]
)
