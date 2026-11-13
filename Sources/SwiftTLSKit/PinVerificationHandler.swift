import NIOCore
import NIOSSL
import NIOTLS

/// Checks the server's leaf certificate against a set of pins once the handshake completes,
/// and lets nothing through in either direction until it has.
///
/// It sits directly after the `NIOSSLClientHandler`. NIOSSL's verification callback *replaces*
/// chain validation rather than adding to it, so a pin enforced there would have to
/// re-implement validation; checking after the handshake keeps NIOSSL's own chain and hostname
/// verification intact and adds the pin on top.
///
/// The cost is that the handshake completes before the pin is judged. What makes that safe is
/// that this handler holds every write issued before the verdict, so no application byte is
/// encrypted for a server that then fails its pin.
final class PinVerificationHandler: ChannelDuplexHandler {
    typealias InboundIn = NIOAny
    typealias InboundOut = NIOAny
    typealias OutboundIn = NIOAny
    typealias OutboundOut = NIOAny

    /// How many writes may wait for the handshake. A client that has queued more than this
    /// before a handshake finishes is not waiting on a handshake.
    static let maximumHeldWrites = 1_024

    private enum Verdict {
        case pending
        case matched
        case refused
    }

    private let pins: [CertificatePin]
    private var verdict = Verdict.pending
    private var heldWrites = CircularBuffer<(data: NIOAny, promise: EventLoopPromise<Void>?)>()
    private var flushRequested = false

    init(pins: [CertificatePin]) {
        self.pins = pins
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        guard case .handshakeCompleted? = event as? TLSUserEvent, verdict == .pending else {
            context.fireUserInboundEventTriggered(event)
            return
        }
        // The failure is not handled here: it is the pipeline's to report, and `refuse` sends
        // it down the pipeline before closing.
        if case .failure(let error) = Result(catching: { try requireMatch(context: context) }) {
            refuse(context: context, error: error)
            return
        }
        verdict = .matched
        // Held writes go first, so that what the application wrote before the handshake is
        // still ahead of anything it writes on hearing that the handshake completed.
        while let held = heldWrites.popFirst() {
            context.write(held.data, promise: held.promise)
        }
        if flushRequested {
            context.flush()
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard verdict == .matched else { return }
        context.fireChannelRead(data)
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        switch verdict {
        case .matched:
            context.write(data, promise: promise)
        case .refused:
            promise?.fail(ChannelError.ioOnClosedChannel)
        case .pending:
            guard heldWrites.count < Self.maximumHeldWrites else {
                promise?.fail(ClientTrustError.tooManyWritesBeforeHandshake(limit: Self.maximumHeldWrites))
                return
            }
            heldWrites.append((data, promise))
        }
    }

    func flush(context: ChannelHandlerContext) {
        guard verdict == .matched else {
            flushRequested = true
            return
        }
        context.flush()
    }

    func channelInactive(context: ChannelHandlerContext) {
        failHeldWrites(ChannelError.ioOnClosedChannel)
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        failHeldWrites(ChannelError.ioOnClosedChannel)
    }

    private func requireMatch(context: ChannelHandlerContext) throws {
        let tls = try context.pipeline.syncOperations.handler(type: NIOSSLClientHandler.self)
        guard let leaf = tls.peerCertificate else {
            throw ClientTrustError.noPeerCertificate
        }
        let presented = try CertificateSummary(leaf)
        let matches = pins.contains { pin in
            switch pin.subject {
            case .certificate: return pin.sha256 == presented.certificateSHA256
            case .publicKey: return pin.sha256 == presented.publicKeySHA256
            }
        }
        guard matches else {
            throw ClientTrustError.pinMismatch(
                certificateSHA256: presented.certificateSHA256, publicKeySHA256: presented.publicKeySHA256)
        }
    }

    private func refuse(context: ChannelHandlerContext, error: any Error) {
        verdict = .refused
        failHeldWrites(error)
        context.fireErrorCaught(error)
        context.close(promise: nil)
    }

    private func failHeldWrites(_ error: any Error) {
        while let held = heldWrites.popFirst() {
            held.promise?.fail(error)
        }
    }
}
