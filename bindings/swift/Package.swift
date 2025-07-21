// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "LibSilver",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(
            name: "LibSilver",
            targets: ["LibSilver"]
        )
    ],
    dependencies: [
        // Add any Swift dependencies here
    ],
    targets: [
        .target(
            name: "LibSilver",
            dependencies: ["LibSilverFFI", "LibSilverRust"],
            path: "Sources/LibSilver"
        ),
        .target(
            name: "LibSilverFFI",
            dependencies: ["LibSilverRust"],
            path: "Sources/LibSilverFFI"
        ),
        .binaryTarget(
            name: "LibSilverRust",
            path: "LibSilver.xcframework"
        ),
        .testTarget(
            name: "LibSilverTests",
            dependencies: ["LibSilver"],
            path: "Tests/LibSilverTests"
        ),
    ]
)
