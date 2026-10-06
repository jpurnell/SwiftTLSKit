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
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        // TEST ONLY. Certificates and keys are generated when the tests run, so no private key
        // is ever checked in. Absent from the library target on purpose.
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
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "SwiftTLSKitTests",
            dependencies: [
                "SwiftTLSKit",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
    ]
)
