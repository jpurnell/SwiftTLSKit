import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOSSL

/// What a reload did.
///
/// Whatever it did, a context is being served afterwards, and every case says which.
public enum ReloadOutcome: Sendable, Hashable {
    /// The files were valid and new connections now get the identity read from them.
    ///
    /// - Parameters:
    ///   - serving: The leaf now served.
    ///   - replacing: The leaf served until this reload.
    case reloaded(serving: CertificateSummary, replacing: CertificateSummary)

    /// The files were valid and hold the chain already being served. Nothing was replaced.
    ///
    /// - Parameter serving: The leaf served, before and after.
    case unchanged(serving: CertificateSummary)

    /// The files were refused. The identity loaded before is still being served.
    ///
    /// - Parameters:
    ///   - error: Why the files were refused.
    ///   - stillServing: The leaf served, before and after.
    case failed(ServerIdentityError, stillServing: CertificateSummary)
}

extension ReloadOutcome: CustomStringConvertible {
    /// A sentence for a log line. It holds paths, names, dates and public fingerprints only.
    public var description: String {
        switch self {
        case .reloaded(let serving, let replacing):
            return "TLS identity reloaded. Now serving \(serving). Was serving \(replacing)."
        case .unchanged(let serving):
            return "TLS identity unchanged. Still serving \(serving)."
        case .failed(let error, let stillServing):
            return "TLS identity reload failed: \(error) Still serving \(stillServing)."
        }
    }
}

/// A server's TLS context that can be replaced from disk while the server keeps running.
///
/// A certificate renewed on disk does nothing for a server that read its certificate at
/// start-up: it goes on serving the old one until it is restarted, and nothing says so until
/// that one expires. This type is the alternative to restarting. It owns the current
/// ``ServerTLSContext``; each new connection takes its handler from whichever context is
/// current at that moment; and ``reload()`` replaces it.
///
/// ## What is guaranteed
///
/// - **A reload validates completely before it replaces anything.** The files go through
///   every check ``ServerIdentity/load(now:)`` makes and a context is built from them; only
///   then is the current context swapped.
/// - **A failed reload changes nothing.** The context loaded before is still current, still
///   served, and the failure is returned as ``ReloadOutcome/failed(_:stillServing:)``.
/// - **Live connections are not touched.** A connection keeps the context it was accepted
///   under for as long as it lasts. Nothing is closed, renegotiated or re-keyed.
/// - **A connection sees one context or the other, never a mixture.** The swap is a single
///   assignment under a lock.
/// - **Reloads do not overlap.** Two callers reloading at once are served one after the other.
///
/// It is a final class with a lock rather than an actor because a channel initializer is
/// synchronous: it has to read the current context without suspending.
///
/// ## Triggering a reload
///
/// The package does not decide when. ``reload()`` and ``reloadIfChanged()`` are the triggers,
/// and ``reloadOnEach(_:report:)`` runs one of them for each element of any asynchronous
/// sequence — a timer, or a stream of `SIGHUP`s. See <doc:ReloadingWithoutRestart>.
public final class ReloadableServerTLS: Sendable {
    /// The files reloaded from.
    public let identity: ServerIdentity

    /// The options every context is built with.
    public let options: ServerTLSOptions

    private let now: @Sendable () -> Date
    private let currentContext: NIOLockedValueBox<ServerTLSContext>
    /// Held for the whole of a reload, so that two do not interleave their read and their swap.
    private let reloading = NIOLock()

    /// Loads the identity for the first time.
    ///
    /// - Parameters:
    ///   - identity: The certificate chain and private key to serve, and to reload from.
    ///   - options: The minimum TLS version and ALPN protocols.
    ///   - now: Called at each load to ask what time it is. The library does not read the
    ///     clock itself; pass `{ Date() }` unless the server has its own source of time.
    /// - Throws: ``ServerIdentityError`` if the identity cannot be served. A server that cannot
    ///   load its identity at start-up has no earlier one to fall back to, so this is an error
    ///   rather than a quiet start without TLS.
    public init(
        identity: ServerIdentity,
        options: ServerTLSOptions = ServerTLSOptions(),
        now: @escaping @Sendable () -> Date
    ) throws(ServerIdentityError) {
        self.identity = identity
        self.options = options
        self.now = now
        self.currentContext = NIOLockedValueBox(try ServerTLSContext.load(identity, options: options, now: now()))
    }

    /// The context new connections are being given.
    public var current: ServerTLSContext {
        currentContext.withLockedValue { $0 }
    }

    /// A TLS handler for one connection, from the current context.
    ///
    /// - Returns: A new `NIOSSLServerHandler`.
    public func makeHandler() -> NIOSSLServerHandler {
        current.makeHandler()
    }

    /// Puts a TLS handler from the current context at the front of a connection's pipeline.
    ///
    /// This is the line a channel initializer calls. Because it reads ``current`` each time,
    /// a connection accepted after a reload gets the reloaded identity.
    ///
    /// - Parameter pipeline: The connection's pipeline.
    /// - Throws: Whatever the pipeline throws if the handler cannot be added.
    public func addHandler(to pipeline: ChannelPipeline.SynchronousOperations) throws {
        try current.addHandler(to: pipeline)
    }

    /// Reads the identity from disk again and, if it is fit to serve, serves it from now on.
    ///
    /// Always rebuilds the context when the files are valid, whether or not they changed. Use
    /// ``reloadIfChanged()`` for a trigger that fires on a schedule.
    ///
    /// - Returns: ``ReloadOutcome/reloaded(serving:replacing:)``, or
    ///   ``ReloadOutcome/failed(_:stillServing:)`` with the previous identity still served.
    @discardableResult
    public func reload() -> ReloadOutcome {
        reloading.withLock { replace(onlyIfChanged: false) }
    }

    /// Reads the identity from disk again and replaces the current one only if the certificate
    /// chain differs.
    ///
    /// The files are validated either way, so a chain that has not changed but has since
    /// expired, or a key whose permissions have been loosened, is still reported as
    /// ``ReloadOutcome/failed(_:stillServing:)``.
    ///
    /// - Returns: ``ReloadOutcome/unchanged(serving:)`` when the chain on disk is the one being
    ///   served; otherwise as ``reload()``.
    @discardableResult
    public func reloadIfChanged() -> ReloadOutcome {
        reloading.withLock { replace(onlyIfChanged: true) }
    }

    /// Calls ``reloadIfChanged()`` once for each element of `triggers`, until it ends.
    ///
    /// The mechanism behind both a periodic check and a `SIGHUP` handler: the caller supplies
    /// the sequence, and this supplies the loop. It returns when the sequence finishes, and
    /// stops early if the task is cancelled.
    ///
    /// - Parameters:
    ///   - triggers: When to check. The elements themselves are ignored.
    ///   - report: Called with each outcome, in order — the place to log it.
    /// - Throws: Only what iterating `triggers` throws.
    public func reloadOnEach<Triggers: AsyncSequence & Sendable>(
        _ triggers: Triggers,
        report: @Sendable (ReloadOutcome) -> Void
    ) async rethrows {
        for try await _ in triggers {
            report(reloadIfChanged())
        }
    }

    private func replace(onlyIfChanged: Bool) -> ReloadOutcome {
        let serving = current
        let candidate: ServerTLSContext
        switch Result(catching: { () throws(ServerIdentityError) in
            try ServerTLSContext.load(identity, options: options, now: now())
        }) {
        case .failure(let error):
            return .failed(error, stillServing: serving.leaf)
        case .success(let loaded):
            candidate = loaded
        }
        if onlyIfChanged, candidate.chainFingerprints == serving.chainFingerprints {
            return .unchanged(serving: serving.leaf)
        }
        currentContext.withLockedValue { $0 = candidate }
        return .reloaded(serving: candidate.leaf, replacing: serving.leaf)
    }
}
