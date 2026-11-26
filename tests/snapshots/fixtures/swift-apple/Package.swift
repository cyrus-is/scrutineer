// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SampleAppleApp",
    targets: [
        .target(name: "SampleApp"),
        .testTarget(name: "SampleAppTests", dependencies: ["SampleApp"]),
    ]
)
