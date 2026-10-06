// swift-tools-version: 6.2
// legibility:description: TLS configuration for SwiftNIO servers and clients, written once — validated server identities, reload without restart, and client trust that cannot be switched off.
//
// 6.2, not the 6.4 `swift package init` wrote from the local toolchain: every sibling package
// declares 6.2, and a tools-version above a consumer's compiler is a resolution failure on the
// machine that matters, discovered at deploy time.

import PackageDescription

let package = Package(
    name: "SwiftTLSKit",
    // macOS 14 is the floor of SwiftMCPServer and VaultMCP, the server-side adopters, and of the
    // x86_64 deployment host. iOS is declared because IconquerClient — a planned adopter of the
    // client half — ships there.
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "SwiftTLSKit", targets: ["SwiftTLSKit"]),
        // For a consumer's TEST targets only: a certificate authority and leaves generated when
        // the tests run, and a server context built from them in memory. It is a separate
        // product so that swift-certificates is linked by a test target that asks for it and
        // by nothing else — `SwiftTLSKit` itself does not depend on it.
        .library(name: "SwiftTLSKitTestSupport", targets: ["SwiftTLSKitTestSupport"]),
    ],
    dependencies: [
        // Floors match VaultMCP's, which are the advisory-fixed versions the portfolio settled
        // on. A lower floor here would let a consumer resolve below them.
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.102.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.37.4"),
        // SHA-256, for certificate and public-key pins and for the fingerprints an operator
        // compares against `openssl`. NIOSSL exposes no digest, and a hand-written one is not
        // something a TLS package should contain. On Apple platforms this is CryptoKit
        // re-exported; every planned adopter already resolves it.
        //
        // A range across two majors, not `from: "3.0.0"`. That floor's implied ceiling excluded
        // 4.x and pulled a consumer already on 4.5.0 back down to 3.15.1. Nothing used here —
        // `SHA256.hash(data:)` and, in the test-support product, P-256 keys — differs between
        // the two, and both ends of the range are built: see CHANGELOG.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        // For `SwiftTLSKitTestSupport` ONLY. Certificates and keys are generated when tests run,
        // so no private key is ever checked in. Absent from the `SwiftTLSKit` target on purpose:
        // a consumer of that product alone resolves these two and never builds or links them.
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.1.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
    ],
    targets: [
        .target(
            name: "SwiftTLSKit",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "SwiftTLSKitTestSupport",
            dependencies: [
                "SwiftTLSKit",
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .testTarget(
            name: "SwiftTLSKitTests",
            dependencies: [
                "SwiftTLSKit",
                "SwiftTLSKitTestSupport",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto"),
                // To read back what the test-support product issued, with a parser that is
                // neither it nor SwiftTLSKit.
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
    ]
)
