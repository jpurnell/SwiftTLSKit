import Crypto
import Foundation
import NIOSSL
import SwiftASN1
@testable import SwiftTLSKit
import Testing
import X509

/// A certificate, built here and not by `SwiftTLSKitTestSupport`, so that the names in it can be
/// of any kind and the reference that reads them back is swift-certificates, which is neither
/// the code under test nor NIOSSL.
private enum SANCertificate {
    /// The scalar 7: a valid P-256 key, fixed, so that nothing here draws on randomness.
    private static let scalar = Data(repeating: 0, count: 31) + [7]

    static func der(_ names: [GeneralName]?) throws -> [UInt8] {
        let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let name = try DistinguishedName { CommonName("san.test") }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(bytes: [0x01, 0x02, 0x03, 0x04]),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: Date(timeIntervalSince1970: 1_546_300_800),
            notValidAfter: Date(timeIntervalSince1970: 1_577_836_800),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                if let names {
                    SubjectAlternativeNames(names)
                }
            },
            issuerPrivateKey: Certificate.PrivateKey(key))
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }

    static func ip(_ bytes: [UInt8]) -> GeneralName {
        .ipAddress(ASN1OctetString(contentBytes: bytes[...]))
    }
}

/// DER written by hand, for the inputs a certificate library would refuse to build.
private enum HandWritten {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let count = content.count
        let length: [UInt8]
        if count < 0x80 {
            length = [UInt8(count)]
        } else if count < 0x100 {
            length = [0x81, UInt8(count)]
        } else {
            length = [0x82, UInt8(count >> 8), UInt8(count & 0xff)]
        }
        return [tag] + length + content
    }

    private static let sanOID: [UInt8] = [0x55, 0x1d, 0x11]

    /// The smallest structure the reader has to walk: a certificate whose only extension is a
    /// subject alternative names extension holding `generalNames`, each already encoded.
    static func certificate(generalNames: [[UInt8]]) -> [UInt8] {
        let names = tlv(0x30, generalNames.flatMap { $0 })
        let extensionValue = tlv(0x30, tlv(0x06, sanOID) + tlv(0x04, names))
        let extensions = tlv(0xa3, tlv(0x30, extensionValue))
        let tbs = tlv(0x30,
            tlv(0xa0, tlv(0x02, [2])) + tlv(0x02, [1]) + tlv(0x30, []) + tlv(0x30, []) + tlv(0x30, [])
                + tlv(0x30, []) + tlv(0x30, []) + extensions)
        return tlv(0x30, tbs + tlv(0x30, []) + tlv(0x03, [0]))
    }

    static func dns(_ bytes: [UInt8]) -> [UInt8] { tlv(0x82, bytes) }
    static func ip(_ bytes: [UInt8]) -> [UInt8] { tlv(0x87, bytes) }
    static func email(_ text: String) -> [UInt8] { tlv(0x81, Array(text.utf8)) }
}

@Suite("Subject alternative names, read from the DER")
struct SubjectAlternativeNameTests {
    // MARK: Golden path

    @Test("DNS names and addresses come back as text, in the order the certificate lists them")
    func goldenPath() throws {
        let der = try SANCertificate.der([
            .dnsName("example.test"), .dnsName("*.example.test"),
            SANCertificate.ip([127, 0, 0, 1]),
            SANCertificate.ip([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ])
        #expect(
            DERSubjectAlternativeNames.names(inCertificateDER: der)
                == ["example.test", "*.example.test", "127.0.0.1", "::1"])
    }

    @Test("A certificate with no subject alternative names has none")
    func noExtension() throws {
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: try SANCertificate.der(nil)).isEmpty)
    }

    @Test("Names that do not name a host are left out, and the ones around them keep their order")
    func otherKindsAreSkipped() throws {
        let der = try SANCertificate.der([
            .dnsName("first.test"),
            .rfc822Name("someone@example.test"),
            .uniformResourceIdentifier("https://uri.example.test/"),
            .directoryName(try DistinguishedName { CommonName("directory") }),
            SANCertificate.ip([10, 0, 0, 7]),
        ])
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: der) == ["first.test", "10.0.0.7"])
    }

    @Test("What the certificate library reads is what this reads: same names, same order, same bytes")
    func agreesWithSwiftCertificates() throws {
        let sets: [[GeneralName]] = [
            [.dnsName("a.test")],
            [SANCertificate.ip([192, 168, 1, 20]), .dnsName("b.test"), SANCertificate.ip([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])],
            [.dnsName("localhost"), .dnsName("tls.example"), SANCertificate.ip([127, 0, 0, 1])],
            [.rfc822Name("x@y.test"), .dnsName("only.test")],
            [.dnsName("a.test"), .dnsName("a.test")],
        ]
        for names in sets {
            let der = try SANCertificate.der(names)
            let reference = try Certificate(derEncoded: der[...]).extensions.subjectAlternativeNames ?? SubjectAlternativeNames([])
            let expected: [String] = reference.compactMap { name in
                switch name {
                case .dnsName(let text): return "dns:\(text)"
                case .ipAddress(let octets): return "ip:" + Array(octets.bytes).map { String($0) }.joined(separator: ",")
                default: return nil
                }
            }
            let actual = DERSubjectAlternativeNames.names(inCertificateDER: der).map(Self.tagged)
            #expect(actual == expected)
        }
    }

    /// Reads a name this package printed back into the form the reference is compared in. A
    /// different route from the one that printed it: split on the separators and expand `::`.
    private static func tagged(_ text: String) -> String {
        if text.contains(":") {
            let halves = text.components(separatedBy: "::")
            func groups(_ side: String) -> [UInt16] {
                side.isEmpty ? [] : side.split(separator: ":").map { UInt16($0, radix: 16) ?? 0xffff }
            }
            let head = groups(halves[0])
            let tail = halves.count > 1 ? groups(halves[1]) : []
            let all = head + Array(repeating: 0, count: halves.count > 1 ? 8 - head.count - tail.count : 0) + tail
            return "ip:" + all.flatMap { [String($0 >> 8), String($0 & 0xff)] }.joined(separator: ",")
        }
        if text.split(separator: ".").count == 4, text.allSatisfy({ $0.isNumber || $0 == "." }) {
            return "ip:" + text.split(separator: ".").joined(separator: ",")
        }
        return "dns:\(text)"
    }

    // MARK: IPv6 text — RFC 5952 section 4

    @Test(
        "An IPv6 address is written as RFC 5952 writes it",
        arguments: [
            // (groups, text)
            ([0, 0, 0, 0, 0, 0, 0, 1], "::1"),
            ([0, 0, 0, 0, 0, 0, 0, 0], "::"),
            ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], "2001:db8::1"),
            // §4.2.2: one group of zeros is not shortened.
            ([0x2001, 0x0db8, 0, 1, 1, 1, 1, 1], "2001:db8:0:1:1:1:1:1"),
            // §4.2.3: the longest run is shortened, the first if they tie.
            ([0x2001, 0x0db8, 0, 0, 1, 0, 0, 1], "2001:db8::1:0:0:1"),
            ([0x2001, 0, 0, 1, 0, 0, 0, 1], "2001:0:0:1::1"),
            ([1, 0, 0, 0, 0, 0, 0, 0], "1::"),
            // §4.1: no leading zeros, and lowercase.
            ([0xfe80, 0, 0, 0, 0, 0, 0, 0x00ab], "fe80::ab"),
            ([0xABCD, 0xEF01, 1, 2, 3, 4, 5, 6], "abcd:ef01:1:2:3:4:5:6"),
            // An IPv4-mapped address stays in hex groups: the form is the same for every address.
            ([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], "::ffff:7f00:1"),
        ] as [([UInt16], String)])
    func rfc5952(groups: [UInt16], text: String) {
        let bytes = groups.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xff)] }
        #expect(DERSubjectAlternativeNames.text(ipv6: bytes) == text)
    }

    // MARK: Hostile input

    @Test("A certificate cut off at any point has no names, and nothing traps")
    func truncation() throws {
        let der = try SANCertificate.der([.dnsName("example.test"), SANCertificate.ip([127, 0, 0, 1])])
        for count in 0..<der.count {
            #expect(DERSubjectAlternativeNames.names(inCertificateDER: Array(der[0..<count])).isEmpty)
        }
    }

    @Test("Whatever one changed byte does to a certificate, every name that comes back is safe to print")
    func everyByteChanged() throws {
        let der = try SANCertificate.der([.dnsName("example.test"), SANCertificate.ip([127, 0, 0, 1])])
        let printable = Unicode.Scalar(0x21)...Unicode.Scalar(0x7e)
        var unsafe: [String] = []
        for index in der.indices {
            for replacement: UInt8 in [0x00, 0x0a, 0x20, 0x7f, 0x80, 0xff] {
                var changed = der
                changed[index] = replacement
                for name in DERSubjectAlternativeNames.names(inCertificateDER: changed)
                where !name.unicodeScalars.allSatisfy({ printable.contains($0) }) {
                    unsafe.append(name)
                }
            }
        }
        #expect(unsafe.isEmpty)
    }

    @Test("A length that claims more than there is gives no names")
    func lengthPastTheEnd() {
        var der = HandWritten.certificate(generalNames: [HandWritten.dns(Array("a.test".utf8))])
        // The outermost length, made larger than the whole.
        der[1] = 0x7f
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: der).isEmpty)
        // A name whose length runs past the extension that holds it.
        let long = HandWritten.certificate(generalNames: [[0x82, 0x40] + Array("a.test".utf8)])
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: long).isEmpty)
    }

    @Test("An indefinite length, which DER forbids, gives no names")
    func indefiniteLength() {
        var der = HandWritten.certificate(generalNames: [HandWritten.dns(Array("a.test".utf8))])
        der[1] = 0x80
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: der).isEmpty)
    }

    @Test("A length of more than four bytes gives no names")
    func hugeLengthField() {
        let der: [UInt8] = [0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x30, 0x00]
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: der).isEmpty)
    }

    @Test("An address that is not four or sixteen bytes is not a name")
    func oddAddressLengths() {
        let der = HandWritten.certificate(generalNames: [
            HandWritten.ip([1, 2, 3]), HandWritten.ip([1, 2, 3, 4, 5]), HandWritten.ip([]),
            HandWritten.ip([10, 0, 0, 1]),
        ])
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: der) == ["10.0.0.1"])
    }

    @Test(
        "A DNS name that could forge or hide a line in a log is not reported",
        arguments: [
            Array("good.test\u{0}evil.test".utf8),
            Array("two\nlines.test".utf8),
            Array("carriage\rreturn.test".utf8),
            Array("tab\there.test".utf8),
            Array("spaced name.test".utf8),
            Array("escape\u{1b}[31m.test".utf8),
            Array("delete\u{7f}.test".utf8),
            Array("caf\u{e9}.test".utf8),
            [0xff, 0xfe, 0x41],
            [],
        ] as [[UInt8]])
    func unprintableNames(name: [UInt8]) {
        let der = HandWritten.certificate(generalNames: [HandWritten.dns(name), HandWritten.dns(Array("kept.test".utf8))])
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: der) == ["kept.test"])
    }

    @Test("A certificate that carries two subject alternative names extensions is read from the first")
    func firstExtensionWins() {
        let sanOID: [UInt8] = [0x55, 0x1d, 0x11]
        func extensionValue(_ name: String) -> [UInt8] {
            HandWritten.tlv(0x30, HandWritten.tlv(0x06, sanOID)
                + HandWritten.tlv(0x04, HandWritten.tlv(0x30, HandWritten.dns(Array(name.utf8)))))
        }
        let extensions = HandWritten.tlv(0xa3, HandWritten.tlv(0x30, extensionValue("first.test") + extensionValue("second.test")))
        let tbs = HandWritten.tlv(0x30,
            HandWritten.tlv(0x02, [1]) + HandWritten.tlv(0x30, []) + extensions)
        let der = HandWritten.tlv(0x30, tbs + HandWritten.tlv(0x30, []) + HandWritten.tlv(0x03, [0]))
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: der) == ["first.test"])
    }

    @Test("Bytes that are not a certificate have no names")
    func notACertificate() {
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: []).isEmpty)
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: [0x30]).isEmpty)
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: Array("not DER at all".utf8)).isEmpty)
        #expect(DERSubjectAlternativeNames.names(inCertificateDER: [UInt8](repeating: 0x30, count: 4096)).isEmpty)
    }

    // MARK: Through the summary

    @Test("The summary prints an IPv6 address as RFC 5952 does, not as eight groups")
    func summaryReportsIPv6Compressed() throws {
        let der = try SANCertificate.der([
            .dnsName("example.test"),
            SANCertificate.ip([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            SANCertificate.ip([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ])
        let summary = try CertificateSummary(NIOSSLCertificate(bytes: der, format: .der))
        #expect(summary.subjectAlternativeNames == ["example.test", "2001:db8::1", "::1"])
    }
}
