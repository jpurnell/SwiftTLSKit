import Crypto
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import SwiftTLSKit

/// Sends back whatever arrives.
final class EchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }
}

/// A TLS echo server on a loopback port the kernel chooses.
struct LoopbackServer {
    let channel: any Channel
    let port: Int

    /// - Parameter addTLS: Adds the TLS handler to a new connection's pipeline. Called once per
    ///   connection, on its event loop — which is where a reloadable context is read from.
    static func start(
        addTLS: @escaping @Sendable (ChannelPipeline.SynchronousOperations) throws -> Void
    ) async throws -> LoopbackServer {
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try addTLS(channel.pipeline.syncOperations)
                    try channel.pipeline.syncOperations.addHandler(EchoHandler())
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        guard let port = channel.localAddress?.port else {
            throw LoopbackError.noPort
        }
        return LoopbackServer(channel: channel, port: port)
    }

    static func start(serving context: ServerTLSContext) async throws -> LoopbackServer {
        try await start { pipeline in try context.addHandler(to: pipeline) }
    }

    func stop() async throws {
        try await channel.close()
    }
}

enum LoopbackError: Error, Equatable {
    case noPort
    case closedBeforeHandshake
    case closedBeforeReply
    /// Nothing happened at all. A guard against a hung suite, not a measurement: the tests
    /// assert on what a handshake ended in, never on how long it took.
    case nothingHappened
}

/// What a client saw once its handshake completed.
struct HandshakeReport: Sendable, Equatable {
    /// SHA-256 of the DER of the certificate the server presented, lowercase hex. Computed
    /// here with swift-crypto from the bytes NIOSSL hands over, not by the library under test.
    let peerCertificateSHA256: String
    let tlsVersion: TLSVersion
    let applicationProtocol: String?
}

/// Sits at the end of a client pipeline and reports the handshake, then carries echoes.
final class ClientProbe: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let handshake: EventLoopPromise<HandshakeReport>
    private var handshakeSettled = false
    private var reply: (expectedBytes: Int, received: ByteBuffer, promise: EventLoopPromise<String>)?

    private var watchdog: Scheduled<Void>?

    /// Long enough that only a hang reaches it.
    private static let watchdogDelay = TimeAmount.seconds(20)

    init(handshake: EventLoopPromise<HandshakeReport>) {
        self.handshake = handshake
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        let probe = NIOLoopBound(self, eventLoop: context.eventLoop)
        watchdog = context.eventLoop.scheduleTask(in: Self.watchdogDelay) {
            probe.value.settle(with: LoopbackError.nothingHappened, replyError: LoopbackError.nothingHappened)
            bound.value.close(promise: nil)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        watchdog?.cancel()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case .handshakeCompleted(let negotiated)? = event as? TLSUserEvent, !handshakeSettled {
            handshakeSettled = true
            do {
                let tls = try context.pipeline.syncOperations.handler(type: NIOSSLClientHandler.self)
                guard let certificate = tls.peerCertificate, let version = tls.tlsVersion else {
                    throw LoopbackError.closedBeforeHandshake
                }
                let digest = SHA256.hash(data: try certificate.toDERBytes())
                watchdog?.cancel()
                handshake.succeed(
                    HandshakeReport(
                        peerCertificateSHA256: digest.map { byte in
                            let text = String(byte, radix: 16)
                            return text.count == 1 ? "0" + text : text
                        }.joined(),
                        tlsVersion: version,
                        applicationProtocol: negotiated))
            } catch {
                handshake.fail(error)
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        guard var pending = reply else { return }
        pending.received.writeBuffer(&incoming)
        guard pending.received.readableBytes >= pending.expectedBytes else {
            reply = pending
            return
        }
        reply = nil
        watchdog?.cancel()
        pending.promise.succeed(String(buffer: pending.received))
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        settle(with: error, replyError: error)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        settle(with: LoopbackError.closedBeforeHandshake, replyError: LoopbackError.closedBeforeReply)
        context.fireChannelInactive()
    }

    func send(_ text: String, context: ChannelHandlerContext, promise: EventLoopPromise<String>) {
        let outgoing = ByteBuffer(string: text)
        reply = (outgoing.readableBytes, ByteBuffer(), promise)
        watchdog?.cancel()
        let probe = NIOLoopBound(self, eventLoop: context.eventLoop)
        watchdog = context.eventLoop.scheduleTask(in: Self.watchdogDelay) {
            probe.value.settle(with: LoopbackError.nothingHappened, replyError: LoopbackError.nothingHappened)
        }
        context.writeAndFlush(NIOAny(outgoing), promise: nil)
    }

    private func settle(with error: any Error, replyError: any Error) {
        if !handshakeSettled {
            handshakeSettled = true
            handshake.fail(error)
        }
        if let pending = reply {
            reply = nil
            pending.promise.fail(replyError)
        }
    }
}

/// A TLS client connected to a loopback port, its handshake already complete.
struct LoopbackClient {
    let channel: any Channel
    let report: HandshakeReport

    /// Connects to `127.0.0.1:port` and waits for the handshake to succeed or fail.
    ///
    /// - Parameter addTLS: Adds the client's TLS handlers to the pipeline.
    /// - Throws: Whatever ended the handshake.
    static func connect(
        port: Int,
        addTLS: @escaping @Sendable (ChannelPipeline.SynchronousOperations) throws -> Void
    ) async throws -> LoopbackClient {
        let loop = MultiThreadedEventLoopGroup.singleton.next()
        let handshake = loop.makePromise(of: HandshakeReport.self)
        let channel: any Channel
        do {
            channel = try await ClientBootstrap(group: loop)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try addTLS(channel.pipeline.syncOperations)
                        try channel.pipeline.syncOperations.addHandler(ClientProbe(handshake: handshake))
                    }
                }
                .connect(host: "127.0.0.1", port: port)
                .get()
        } catch {
            handshake.fail(error)
            throw error
        }
        do {
            return LoopbackClient(channel: channel, report: try await handshake.futureResult.get())
        } catch {
            try? await channel.close()
            throw error
        }
    }

    static func connect(port: Int, context: ClientTLSContext, serverHostname: String) async throws -> LoopbackClient {
        try await connect(port: port) { pipeline in
            try context.addHandlers(to: pipeline, serverHostname: serverHostname)
        }
    }

    /// A client built from a bare NIOSSL configuration, for asking what the *server* refuses.
    static func connect(port: Int, configuration: TLSConfiguration, serverHostname: String) async throws -> LoopbackClient {
        let context = try NIOSSLContext(configuration: configuration)
        return try await connect(port: port) { pipeline in
            try pipeline.addHandler(NIOSSLClientHandler(context: context, serverHostname: serverHostname))
        }
    }

    /// Sends `text` and waits for the server to echo all of it back.
    func roundTrip(_ text: String) async throws -> String {
        let promise = channel.eventLoop.makePromise(of: String.self)
        let channel = self.channel
        channel.eventLoop.execute {
            do {
                let context = try channel.pipeline.syncOperations.context(handlerType: ClientProbe.self)
                let probe = try channel.pipeline.syncOperations.handler(type: ClientProbe.self)
                probe.send(text, context: context, promise: promise)
            } catch {
                promise.fail(error)
            }
        }
        return try await promise.futureResult.get()
    }

    func close() async throws {
        try await channel.close()
    }
}

/// Why a handshake did not complete, reduced to what the tests distinguish.
enum HandshakeFailure: Equatable {
    /// The certificate chain did not lead to a trusted root.
    case untrustedCertificate
    /// The certificate does not name the host asked for.
    case hostnameMismatch
    /// The two sides share no protocol version.
    case noSharedProtocolVersion
    /// Anything else, verbatim, so an unexpected failure is legible in the test output.
    case other(String)

    init(_ error: any Error) {
        let text = String(describing: error)
        if let extra = error as? NIOSSLExtraError, extra == .failedToValidateHostname {
            self = .hostnameMismatch
        } else if text.contains("CERTIFICATE_VERIFY_FAILED") {
            self = .untrustedCertificate
        } else if text.contains("PROTOCOL_VERSION") || text.contains("UNSUPPORTED_PROTOCOL") {
            self = .noSharedProtocolVersion
        } else {
            self = .other(text)
        }
    }

    /// The failure `body` ends in, or `nil` if it did not fail.
    static func of(_ body: () async throws -> LoopbackClient) async -> HandshakeFailure? {
        do {
            let client = try await body()
            try? await client.close()
            return nil
        } catch {
            return HandshakeFailure(error)
        }
    }
}
