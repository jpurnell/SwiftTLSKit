/// Reads the DNS names and IP addresses from a certificate's subject alternative names.
///
/// This exists so that ``CertificateSummary`` need not call NIOSSL's `_subjectAlternativeNames()`,
/// whose leading underscore is NIOSSL's word that it may change, and need not import a
/// certificate-parsing library into the library target. It reads the DER that
/// `NIOSSLCertificate.toDERBytes()` returns, which is stable.
///
/// The certificate it is given has already been parsed and accepted by BoringSSL, and the names
/// it returns go into a log line. So it is lenient about what X.509 allows and strict about what
/// a log line can hold: anything it cannot read gives no names rather than an error, and a name
/// that could not be printed safely is left out rather than printed.
///
/// Reading follows RFC 5280 section 4.1 for the shape of a certificate, section 4.2.1.6 for the
/// extension, and X.690 for the encoding. The structure is fixed and shallow, so there is no
/// recursion, and every length is checked against the bytes that remain before it is used.
enum DERSubjectAlternativeNames {
    /// The DNS names and IP addresses in a certificate's subject alternative names extension, in
    /// the order the certificate lists them.
    ///
    /// DNS names are reported as they are, and so may be wildcards. An address is four bytes
    /// (dotted decimal) or sixteen (RFC 5952). Names of any other kind are left out, as are
    /// addresses of any other length and DNS names that are empty or hold anything but printable
    /// ASCII: a control character, a space or a byte above 0x7e could forge or hide a line in the
    /// log the summary is printed to, and none of them is a name a client will have matched.
    ///
    /// - Parameter der: The certificate, DER encoded.
    /// - Returns: The names; empty if there are none, or if `der` is not a certificate this can
    ///   read. Never traps and never throws.
    static func names(inCertificateDER der: [UInt8]) -> [String] {
        guard let extensionValue = subjectAlternativeNamesValue(in: der) else { return [] }
        var names: [String] = []
        // The value is a SEQUENCE OF GeneralName.
        var outer = Reader(der: extensionValue.bytes, within: extensionValue.range)
        guard let sequence = outer.next(), sequence.tag == Tag.sequence else { return [] }
        var generalNames = Reader(der: extensionValue.bytes, within: sequence.content)
        while let generalName = generalNames.next() {
            let content = Array(extensionValue.bytes[generalName.content])
            switch generalName.tag {
            case Tag.dnsName:
                if let name = dnsName(content) { names.append(name) }
            case Tag.ipAddress:
                if let address = ipAddress(content) { names.append(address) }
            default:
                continue
            }
        }
        return names
    }

    // MARK: - Finding the extension

    /// The bytes inside the first subject alternative names extension, as the array they are in
    /// and the range of it that is the extension's value.
    ///
    /// ```
    /// Certificate  ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    /// TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer, validity,
    ///                               subject, subjectPublicKeyInfo, [1] .., [2] .., [3] extensions }
    /// Extensions   ::= SEQUENCE OF Extension
    /// Extension    ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE,
    ///                             extnValue OCTET STRING }
    /// ```
    private static func subjectAlternativeNamesValue(in der: [UInt8]) -> (bytes: [UInt8], range: Range<Int>)? {
        var top = Reader(der: der, within: der.startIndex..<der.endIndex)
        guard let certificate = top.next(), certificate.tag == Tag.sequence else { return nil }
        var certificateFields = Reader(der: der, within: certificate.content)
        guard let toBeSigned = certificateFields.next(), toBeSigned.tag == Tag.sequence else { return nil }

        var fields = Reader(der: der, within: toBeSigned.content)
        while let field = fields.next() {
            guard field.tag == Tag.extensionsField else { continue }
            var wrapper = Reader(der: der, within: field.content)
            guard let list = wrapper.next(), list.tag == Tag.sequence else { return nil }
            var extensions = Reader(der: der, within: list.content)
            while let candidate = extensions.next() {
                guard candidate.tag == Tag.sequence else { continue }
                if let value = valueIfSubjectAlternativeNames(candidate, in: der) { return (der, value) }
            }
            return nil
        }
        return nil
    }

    /// The range of an extension's value if the extension is a subject alternative names one.
    private static func valueIfSubjectAlternativeNames(_ element: Element, in der: [UInt8]) -> Range<Int>? {
        var parts = Reader(der: der, within: element.content)
        guard let identifier = parts.next(), identifier.tag == Tag.objectIdentifier,
            der[identifier.content].elementsEqual(subjectAlternativeNamesOID)
        else { return nil }
        guard var next = parts.next() else { return nil }
        if next.tag == Tag.boolean {
            guard let afterCritical = parts.next() else { return nil }
            next = afterCritical
        }
        return next.tag == Tag.octetString ? next.content : nil
    }

    // MARK: - Names

    private static func dnsName(_ bytes: [UInt8]) -> String? {
        guard !bytes.isEmpty, bytes.allSatisfy({ printableASCII.contains($0) }) else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func ipAddress(_ bytes: [UInt8]) -> String? {
        switch bytes.count {
        case ipv4ByteCount: return bytes.map { String($0) }.joined(separator: ".")
        case ipv6ByteCount: return text(ipv6: bytes)
        default: return nil
        }
    }

    /// An IPv6 address as RFC 5952 section 4 writes it: lowercase hex, no leading zeros in a
    /// group, and the longest run of two or more zero groups written `::` — the first, if two
    /// are as long. An IPv4-mapped address stays in hex groups, so that the form is the same for
    /// every address.
    ///
    /// - Parameter bytes: Sixteen bytes.
    /// - Returns: The text; empty if `bytes` is not sixteen long.
    static func text(ipv6 bytes: [UInt8]) -> String {
        guard bytes.count == ipv6ByteCount else { return "" }
        let groups = stride(from: 0, to: ipv6ByteCount, by: ipv6GroupByteCount).map { index in
            UInt16(bytes[index]) << byteBits | UInt16(bytes[index + 1])
        }

        var longest = 0..<0
        var runStart = groups.startIndex
        while runStart < groups.endIndex {
            guard groups[runStart] == 0 else {
                runStart += 1
                continue
            }
            var runEnd = runStart
            while runEnd < groups.endIndex, groups[runEnd] == 0 { runEnd += 1 }
            if runEnd - runStart > longest.count { longest = runStart..<runEnd }
            runStart = runEnd
        }
        // A single group of zeros is written as a group, not shortened (section 4.2.2).
        guard longest.count >= minimumShortenedRun else {
            return groups.map { String($0, radix: hexRadix) }.joined(separator: ":")
        }
        let head = groups[..<longest.lowerBound].map { String($0, radix: hexRadix) }.joined(separator: ":")
        let tail = groups[longest.upperBound...].map { String($0, radix: hexRadix) }.joined(separator: ":")
        return head + "::" + tail
    }

    // MARK: - Constants

    private static let ipv4ByteCount = 4
    private static let ipv6ByteCount = 16
    private static let ipv6GroupByteCount = 2
    private static let byteBits: UInt16 = 8
    private static let hexRadix = 16
    private static let minimumShortenedRun = 2
    /// `!` to `~`: every printable ASCII character except the space.
    private static let printableASCII: ClosedRange<UInt8> = 0x21...0x7e
    /// 2.5.29.17, `id-ce-subjectAltName`, as the content of an OBJECT IDENTIFIER.
    private static let subjectAlternativeNamesOID: [UInt8] = [0x55, 0x1d, 0x11]

    /// The tags this reads, as X.690 encodes them.
    private enum Tag {
        static let boolean: UInt8 = 0x01
        static let octetString: UInt8 = 0x04
        static let objectIdentifier: UInt8 = 0x06
        static let sequence: UInt8 = 0x30
        /// `[3]`, constructed: the extensions of a certificate.
        static let extensionsField: UInt8 = 0xa3
        /// `[2]`, primitive: a `GeneralName`'s `dNSName`.
        static let dnsName: UInt8 = 0x82
        /// `[7]`, primitive: a `GeneralName`'s `iPAddress`.
        static let ipAddress: UInt8 = 0x87
    }

    // MARK: - Reading DER

    /// One element: its tag, and where its content is.
    private struct Element {
        let tag: UInt8
        let content: Range<Int>
    }

    /// Walks the elements that sit one after another inside a range, without going into them.
    ///
    /// `next()` returns `nil` at the end of the range, and also at anything it cannot read: a
    /// multi-byte tag, an indefinite length, a length of more than four bytes, or a length that
    /// claims more than the range holds. After that it keeps returning `nil`.
    private struct Reader {
        private let der: [UInt8]
        private var position: Int
        private let end: Int

        private static let multiByteTagMarker: UInt8 = 0x1f
        private static let longFormFlag: UInt8 = 0x80
        private static let longFormCountMask: UInt8 = 0x7f
        private static let maximumLengthBytes = 4

        init(der: [UInt8], within range: Range<Int>) {
            self.der = der
            position = range.lowerBound
            end = range.upperBound
        }

        mutating func next() -> Element? {
            guard position < end else { return nil }
            let tag = der[position]
            guard tag & Self.multiByteTagMarker != Self.multiByteTagMarker, let length = length(after: position) else {
                position = end
                return nil
            }
            // `length.count` has been checked against `end`, so neither sum can overflow.
            let contentStart = length.contentStart
            let content = contentStart..<(contentStart + length.count)
            position = content.upperBound
            return Element(tag: tag, content: content)
        }

        /// The length that follows the tag at `tagPosition`, and where the content starts, or
        /// `nil` if it is not one this reads or claims more than the range holds.
        private func length(after tagPosition: Int) -> (count: Int, contentStart: Int)? {
            var cursor = tagPosition + 1
            guard cursor < end else { return nil }
            let first = der[cursor]
            cursor += 1
            var count: Int
            if first & Self.longFormFlag == 0 {
                count = Int(first)
            } else {
                let lengthBytes = Int(first & Self.longFormCountMask)
                // Zero is the indefinite form, which DER does not allow.
                guard lengthBytes >= 1, lengthBytes <= Self.maximumLengthBytes, end - cursor >= lengthBytes else {
                    return nil
                }
                count = 0
                for _ in 0..<lengthBytes {
                    count = count << Self.byteShift | Int(der[cursor])
                    cursor += 1
                }
            }
            guard count <= end - cursor else { return nil }
            return (count, cursor)
        }

        private static let byteShift = 8
    }
}
