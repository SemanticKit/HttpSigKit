// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "HttpSigKit",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .visionOS(.v26)
    ],
    products: [
        .library(
            name: "HttpSigKit",
            targets: ["HttpSigKit"]
        )
    ],
    targets: [
        .target(
            name: "HttpSigKit"
        ),
        .testTarget(
            name: "HttpSigKitTests",
            dependencies: ["HttpSigKit"]
        )
    ]
)
