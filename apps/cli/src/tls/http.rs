//! ureq exposes either webpki roots or specific DER certificates, but no union.
//! Use its transport API with the same rustls config as WSS to retain both.

use std::io::{Read, Write};
use std::sync::Arc;

use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout,
    RustlsConnector, TcpConnector, Transport, TransportAdapter,
};

pub(super) fn agent(config: ureq::config::Config, tls: Arc<rustls::ClientConfig>) -> ureq::Agent {
    ureq::Agent::with_parts(config, tls_connector(tls), DefaultResolver::default())
}

fn tls_connector(tls: Arc<rustls::ClientConfig>) -> impl Connector<Out = impl Transport> {
    ().chain(ConnectProxyConnector::default())
        .chain(TcpConnector::default())
        .chain(TlsConnector(tls))
}

/// An agent whose every socket read and every socket write gives up after
/// `idle` without moving a byte: ureq's own body timeouts are total budgets,
/// so a long streaming download or upload needs this per-I/O bound to fail a
/// stalled transfer (`Timeout::PerRead` / `Timeout::PerWrite`) instead of
/// hanging until the kernel gives up, while a slow but moving one never
/// trips it. The bound wraps exactly the raw TCP socket, below every TLS
/// layer: a TLS adapter counts its timeout down across the socket operations
/// of one TLS write or read, so a bound above any TLS (the target's, or an
/// HTTPS CONNECT proxy's under the tunnel) would be an aggregate budget, not
/// an idle one. `ConnectProxyConnector` opens the proxy connection by
/// running this whole chain again (TCP → idle → proxy TLS), then returns the
/// tunnel, which [`IdleSocket`] passes through unwrapped before target TLS.
/// The wait for response headers keeps the agent's (or request's) own
/// `timeout_recv_response` when one is set: after an upload's last write the
/// kernel buffer may still be draining, so no byte arrives for a while.
pub(super) fn idle_agent(
    config: ureq::config::Config,
    tls: Option<Arc<rustls::ClientConfig>>,
    idle: std::time::Duration,
) -> ureq::Agent {
    match tls {
        Some(tls) => ureq::Agent::with_parts(
            config,
            idle_layered(TcpConnector::default(), idle, TlsConnector(tls)),
            DefaultResolver::default(),
        ),
        None => ureq::Agent::with_parts(
            config,
            idle_layered(TcpConnector::default(), idle, RustlsConnector::default()),
            DefaultResolver::default(),
        ),
    }
}

/// The idle agent's layering, shared by production and its tests: CONNECT
/// proxy, then the socket connector with the idle bound around each socket
/// it opens, then TLS (or a stand-in) above it.
fn idle_layered<C, L>(socket: C, idle: std::time::Duration, tls: L) -> impl Connector<Out = L::Out>
where
    C: Connector,
    L: Connector<Either<<ConnectProxyConnector as Connector>::Out, Idle<C::Out>>>,
{
    ().chain(ConnectProxyConnector::default())
        .chain(IdleSocket { socket, idle })
        .chain(tls)
}

/// Opens a socket through `socket` and wraps it, and only it, in the idle
/// bound. A transport chained from earlier (a CONNECT tunnel, whose own
/// socket this connector already wrapped while the proxy chain ran) passes
/// through as is.
#[derive(Debug)]
struct IdleSocket<C> {
    socket: C,
    idle: std::time::Duration,
}

impl<In: Transport, C: Connector> Connector<In> for IdleSocket<C> {
    type Out = Either<In, Idle<C::Out>>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        if let Some(chained) = chained {
            return Ok(Some(Either::A(chained)));
        }
        Ok(self.socket.connect(details, None)?.map(|inner| {
            Either::B(Idle {
                inner,
                idle: self.idle,
            })
        }))
    }
}

/// Clamps each socket input and output wait to the idle bound, reporting a
/// clamped expiry as `PerRead` / `PerWrite` (the cause `stalled`).
#[derive(Debug)]
struct Idle<T> {
    inner: T,
    idle: std::time::Duration,
}

impl<T: Transport> Idle<T> {
    fn clamp(&self, timeout: NextTimeout, reason: ureq::Timeout) -> NextTimeout {
        use ureq::unversioned::transport::time::Duration;
        // A bounded response-header wait is its own budget (see `idle_agent`),
        // for input only: a write during that wait (a TLS flush) is still a
        // write and keeps the write-idle bound.
        if reason == ureq::Timeout::PerRead
            && timeout.reason == ureq::Timeout::RecvResponse
            && matches!(timeout.after, Duration::Exact(_))
        {
            return timeout;
        }
        let idle: Duration = self.idle.into();
        if idle < timeout.after {
            NextTimeout {
                after: idle,
                reason,
                ..timeout
            }
        } else {
            timeout
        }
    }
}

impl<T: Transport> Transport for Idle<T> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let timeout = self.clamp(timeout, ureq::Timeout::PerWrite);
        self.inner.transmit_output(amount, timeout)
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let timeout = self.clamp(timeout, ureq::Timeout::PerRead);
        self.inner.await_input(timeout)
    }

    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }

    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }
}

#[derive(Debug)]
struct TlsConnector(Arc<rustls::ClientConfig>);

impl<In: Transport> Connector<In> for TlsConnector {
    type Out = Either<In, TlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Err(ureq::Error::ConnectionFailed);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let host = details
            .uri
            .host()
            .ok_or(ureq::Error::Tls("missing TLS host"))?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|_| ureq::Error::Tls("invalid TLS host"))?
            .to_owned();
        let mut conn = rustls::ClientConnection::new(self.0.clone(), name)?;
        let mut sock = TransportAdapter::new(transport.boxed(), details.current_time.clone());
        // Earlier connectors already spent part of the connect/global budget.
        // The adapter continues counting down across every TLS handshake I/O.
        let timeout =
            remaining_connect_timeout(details.timeout, details.now, (details.current_time)());
        sock.set_timeout(timeout);
        conn.complete_io(&mut sock)?;
        Ok(Some(Either::B(TlsTransport {
            stream: rustls::StreamOwned::new(conn, sock),
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
        })))
    }
}

fn remaining_connect_timeout(
    mut timeout: NextTimeout,
    started: ureq::unversioned::transport::time::Instant,
    now: ureq::unversioned::transport::time::Instant,
) -> NextTimeout {
    use ureq::unversioned::transport::time::{Duration, Instant};
    if let Duration::Exact(limit) = timeout.after {
        let elapsed = match (started, now) {
            (Instant::Exact(start), Instant::Exact(now)) => now.saturating_duration_since(start),
            (_, Instant::AlreadyHappened) | (Instant::NotHappening, Instant::Exact(_)) => {
                std::time::Duration::ZERO
            }
            _ => limit,
        };
        timeout.after = limit.saturating_sub(elapsed).into();
    }
    timeout
}

struct TlsTransport {
    stream: rustls::StreamOwned<rustls::ClientConnection, TransportAdapter>,
    buffers: LazyBuffers,
}

impl Transport for TlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        let output = self
            .buffers
            .output()
            .get(..amount)
            .ok_or(ureq::Error::Tls("invalid TLS output length"))?;
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        let amount = self.stream.read(self.buffers.input_append_buf())?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.sock.get_mut().is_open()
    }
    fn is_tls(&self) -> bool {
        true
    }
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use ureq::unversioned::transport::time::Instant as TransportInstant;

    #[derive(Debug)]
    struct ClockedTransport {
        buffers: LazyBuffers,
        elapsed: Arc<AtomicU64>,
        observed: Arc<Mutex<Vec<NextTimeout>>>,
    }

    impl Transport for ClockedTransport {
        fn buffers(&mut self) -> &mut dyn Buffers {
            &mut self.buffers
        }

        fn transmit_output(&mut self, _: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
            self.observed.lock().unwrap().push(timeout.for_write());
            self.elapsed.fetch_add(400, Ordering::Relaxed);
            Ok(())
        }

        fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
            let timeout = timeout.for_read();
            self.observed.lock().unwrap().push(timeout);
            Err(ureq::Error::Timeout(timeout.reason))
        }

        fn is_open(&mut self) -> bool {
            true
        }
    }

    #[test]
    fn tls_handshake_preserves_elapsed_budgets_and_per_io_limits() {
        use ureq::Timeout;
        use ureq::unversioned::transport::time::Instant as TransportInstant;

        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let connector = TlsConnector(Arc::new(tls));
        let uri = "https://example.test/".parse().unwrap();
        let config = ureq::Agent::config_builder().build();
        let resolver = DefaultResolver::default();
        for reason in [Timeout::Connect, Timeout::Global] {
            for per_io in [false, true] {
                let started = Instant::now();
                // DNS/proxy/TCP consumed 600 ms before TLS starts.
                let elapsed = Arc::new(AtomicU64::new(600));
                let observed = Arc::new(Mutex::new(Vec::new()));
                let clock = elapsed.clone();
                let details = ConnectionDetails {
                    uri: &uri,
                    addrs: ureq::unversioned::resolver::ResolvedSocketAddrs::from_fn(|_| {
                        ([127, 0, 0, 1], 443).into()
                    }),
                    config: &config,
                    request_level: false,
                    resolver: &resolver,
                    now: TransportInstant::Exact(started),
                    timeout: NextTimeout {
                        after: Duration::from_secs(3).into(),
                        reason,
                        per_read: per_io.then(|| Duration::from_millis(1500).into()),
                        per_write: per_io.then(|| Duration::from_millis(1200).into()),
                    },
                    current_time: Arc::new(move || {
                        TransportInstant::Exact(
                            started + Duration::from_millis(clock.load(Ordering::Relaxed)),
                        )
                    }),
                    run_connector: Arc::new(|_| Err(ureq::Error::ConnectionFailed)),
                    register_shutdown: Arc::new(|_| Ok(())),
                };
                let transport = ClockedTransport {
                    buffers: LazyBuffers::new(4096, 4096),
                    elapsed,
                    observed: observed.clone(),
                };
                let error = connector.connect(&details, Some(transport)).unwrap_err();
                assert!(matches!(error, ureq::Error::Timeout(_)), "{error:?}");
                let expected = if per_io {
                    [(1200, Timeout::PerWrite), (1500, Timeout::PerRead)]
                } else {
                    [(2400, reason), (2000, reason)]
                };
                let observed = observed.lock().unwrap();
                assert_eq!(observed.len(), expected.len());
                for (actual, (millis, reason)) in observed.iter().zip(expected) {
                    assert_eq!(actual.after, Duration::from_millis(millis).into());
                    assert_eq!(actual.reason, reason);
                }
            }
        }
    }

    #[test]
    fn exhausted_connect_budget_stays_exhausted_and_unbounded_stays_unbounded() {
        use ureq::Timeout;
        use ureq::unversioned::transport::time::Instant as TransportInstant;

        let started = TransportInstant::now();
        let now = started + Duration::from_secs(4).into();
        let timeout = NextTimeout {
            after: Duration::from_secs(3).into(),
            reason: Timeout::Connect,
            per_read: Some(Duration::from_secs(1).into()),
            ..NextTimeout::default()
        };
        let exhausted = remaining_connect_timeout(timeout, started, now);
        assert_eq!(exhausted.after, Duration::ZERO.into());
        assert_eq!(exhausted.reason, timeout.reason);
        assert_eq!(exhausted.per_read, timeout.per_read);
        let unbounded = NextTimeout::default();
        assert_eq!(
            remaining_connect_timeout(unbounded, started, now),
            unbounded
        );
    }

    #[test]
    fn idle_bound_preserves_stricter_io_and_global_budgets() {
        let idle = Idle {
            inner: ClockedTransport {
                buffers: LazyBuffers::new(4096, 4096),
                elapsed: Arc::default(),
                observed: Arc::default(),
            },
            idle: Duration::from_secs(2),
        };
        let timeout = NextTimeout {
            after: Duration::from_secs(3).into(),
            reason: ureq::Timeout::Global,
            per_read: Some(Duration::from_secs(1).into()),
            per_write: Some(Duration::from_secs(4).into()),
        };
        let clamped = idle.clamp(timeout, ureq::Timeout::PerRead);
        assert_eq!(clamped.after, Duration::from_secs(2).into());
        assert_eq!(clamped.reason, ureq::Timeout::PerRead);
        assert_eq!(clamped.for_read().after, Duration::from_secs(1).into());
        assert_eq!(clamped.for_read().reason, ureq::Timeout::PerRead);
        assert_eq!(clamped.per_write, timeout.per_write);
        // Writes are clamped too, and a clamped expiry reads as a stall.
        let write = idle.clamp(timeout, ureq::Timeout::PerWrite).for_write();
        assert_eq!(write.after, Duration::from_secs(2).into());
        assert_eq!(write.reason, ureq::Timeout::PerWrite);
        let tighter = NextTimeout {
            after: Duration::from_millis(500).into(),
            ..timeout
        };
        for reason in [ureq::Timeout::PerRead, ureq::Timeout::PerWrite] {
            assert_eq!(idle.clamp(tighter, reason).after, tighter.after);
            assert_eq!(idle.clamp(tighter, reason).reason, ureq::Timeout::Global);
        }
        // An unbounded wait is bounded by the idle limit.
        let unbounded = idle.clamp(NextTimeout::default(), ureq::Timeout::PerWrite);
        assert_eq!(unbounded.after, Duration::from_secs(2).into());
        assert_eq!(unbounded.reason, ureq::Timeout::PerWrite);
        // A bounded response-header wait keeps its own (longer) budget; an
        // unbounded one does not escape the idle bound.
        let response = NextTimeout {
            after: Duration::from_secs(300).into(),
            reason: ureq::Timeout::RecvResponse,
            ..NextTimeout::default()
        };
        assert_eq!(idle.clamp(response, ureq::Timeout::PerRead), response);
        // A write during that wait keeps the write-idle bound.
        let write = idle.clamp(response, ureq::Timeout::PerWrite);
        assert_eq!(write.after, Duration::from_secs(2).into());
        assert_eq!(write.reason, ureq::Timeout::PerWrite);
        let unbounded_response = NextTimeout {
            reason: ureq::Timeout::RecvResponse,
            ..NextTimeout::default()
        };
        assert_eq!(
            idle.clamp(unbounded_response, ureq::Timeout::PerRead).after,
            Duration::from_secs(2).into()
        );
    }

    /// One socket: each write moves its bytes in `step_ms` of fake time
    /// until `stop_after` writes, then never, so it fails at its bound; a
    /// read after a write answers `200` (the peer, or a CONNECT proxy, took
    /// the whole request), a read with nothing to answer sees EOF.
    #[derive(Debug)]
    struct PacedSocket {
        buffers: LazyBuffers,
        clock: Arc<AtomicU64>,
        step_ms: u64,
        stop_after: Option<u64>,
        moved: u64,
        writes: Arc<AtomicU64>,
        unanswered: bool,
    }

    impl Transport for PacedSocket {
        fn buffers(&mut self) -> &mut dyn Buffers {
            &mut self.buffers
        }

        fn transmit_output(&mut self, _: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
            use ureq::unversioned::transport::time::Duration as Bound;
            let timeout = timeout.for_write();
            let bound = match timeout.after {
                Bound::Exact(bound) => Some(u64::try_from(bound.as_millis()).unwrap()),
                Bound::NotHappening => None,
            };
            let stopped = self.stop_after.is_some_and(|stop| self.moved >= stop);
            if stopped || bound.is_some_and(|bound| bound < self.step_ms) {
                let bound = bound.expect("an unbounded stalled write would hang");
                self.clock.fetch_add(bound, Ordering::Relaxed);
                return Err(ureq::Error::Timeout(timeout.reason));
            }
            self.clock.fetch_add(self.step_ms, Ordering::Relaxed);
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.moved += 1;
            self.unanswered = true;
            Ok(())
        }

        fn await_input(&mut self, _: NextTimeout) -> Result<bool, ureq::Error> {
            if !self.unanswered {
                return Ok(false);
            }
            self.unanswered = false;
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            self.buffers.input_append_buf()[..response.len()].copy_from_slice(response);
            self.buffers.input_appended(response.len());
            Ok(true)
        }

        fn is_open(&mut self) -> bool {
            true
        }
    }

    /// Makes the agent's socket a `PacedSocket` (no network), or, as
    /// `TcpConnector` does, passes a chained transport (a tunnel) through.
    #[derive(Debug)]
    struct PacedConnector {
        clock: Arc<AtomicU64>,
        step_ms: u64,
        stop_after: Option<u64>,
        writes: Arc<AtomicU64>,
    }

    impl<In: Transport> Connector<In> for PacedConnector {
        type Out = Either<In, PacedSocket>;

        fn connect(
            &self,
            _: &ConnectionDetails,
            chained: Option<In>,
        ) -> Result<Option<Self::Out>, ureq::Error> {
            if let Some(chained) = chained {
                return Ok(Some(Either::A(chained)));
            }
            Ok(Some(Either::B(PacedSocket {
                buffers: LazyBuffers::new(SOCKET_WRITE, SOCKET_WRITE),
                clock: self.clock.clone(),
                step_ms: self.step_ms,
                stop_after: self.stop_after,
                moved: 0,
                writes: self.writes.clone(),
                unanswered: false,
            })))
        }
    }

    const SOCKET_WRITE: usize = 1024;
    /// One TLS-layer write: 12 socket writes.
    const FRAME: usize = 12 * SOCKET_WRITE;

    /// The TLS layer's stand-in: one transport write becomes many socket
    /// writes through a `TransportAdapter` that counts its timeout down
    /// across them on the fake clock, exactly as `TlsTransport` does.
    struct Framing<T: Transport> {
        adapter: TransportAdapter<T>,
        buffers: LazyBuffers,
        flush_on_read: bool,
    }

    impl<T: Transport> std::fmt::Debug for Framing<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Framing").finish_non_exhaustive()
        }
    }

    impl<T: Transport> Transport for Framing<T> {
        fn buffers(&mut self) -> &mut dyn Buffers {
            &mut self.buffers
        }

        fn transmit_output(
            &mut self,
            amount: usize,
            timeout: NextTimeout,
        ) -> Result<(), ureq::Error> {
            self.adapter.set_timeout(timeout);
            let output = self.buffers.output()[..amount].to_vec();
            self.adapter.write_all(&output)?;
            Ok(())
        }

        fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
            self.adapter.set_timeout(timeout);
            if self.flush_on_read {
                // As a TLS read can first flush pending ciphertext.
                self.adapter.write_all(&[0x15])?;
            }
            let read = self.adapter.read(self.buffers.input_append_buf())?;
            self.buffers.input_appended(read);
            Ok(read > 0)
        }

        fn is_open(&mut self) -> bool {
            true
        }
    }

    struct FramingConnector(Arc<dyn Fn() -> TransportInstant + Send + Sync>, bool);

    impl std::fmt::Debug for FramingConnector {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FramingConnector").finish_non_exhaustive()
        }
    }

    impl<In: Transport> Connector<In> for FramingConnector {
        type Out = Framing<In>;

        fn connect(
            &self,
            _: &ConnectionDetails,
            chained: Option<In>,
        ) -> Result<Option<Self::Out>, ureq::Error> {
            Ok(chained.map(|inner| Framing {
                adapter: TransportAdapter::new(inner, self.0.clone()),
                buffers: LazyBuffers::new(FRAME, FRAME),
                flush_on_read: self.1,
            }))
        }
    }

    /// The earlier layering's idle connector: wraps whatever transport the
    /// chain has so far, so after TLS (or a tunnel) it sits above TLS.
    #[derive(Debug)]
    struct IdleConnector(Duration);

    impl<In: Transport> Connector<In> for IdleConnector {
        type Out = Idle<In>;

        fn connect(
            &self,
            _: &ConnectionDetails,
            chained: Option<In>,
        ) -> Result<Option<Self::Out>, ureq::Error> {
            Ok(chained.map(|inner| Idle {
                inner,
                idle: self.0,
            }))
        }
    }

    /// The production layering (`idle_layered`, as `idle_agent` builds it)
    /// with a paced socket and the TLS stand-in, on a fake clock: a body
    /// whose socket writes keep moving for more than three idle intervals is
    /// sent, one whose socket stops fails `PerWrite` (stalled) at the bound.
    /// Putting the bound above TLS (the earlier layering) fails the moving
    /// body, so reverting `idle_layered`'s order fails this test.
    #[test]
    fn idle_bound_below_tls_is_per_socket_write_not_an_aggregate() {
        let idle = Duration::from_secs(1);
        let send = |stopped: bool, production: bool| {
            let clock = Arc::new(AtomicU64::new(0));
            let writes = Arc::new(AtomicU64::new(0));
            let paced = PacedConnector {
                clock: clock.clone(),
                step_ms: 400,
                stop_after: stopped.then_some(0),
                writes: writes.clone(),
            };
            let started = Instant::now();
            let fake = clock.clone();
            let now: Arc<dyn Fn() -> TransportInstant + Send + Sync> = Arc::new(move || {
                TransportInstant::Exact(
                    started + Duration::from_millis(fake.load(Ordering::Relaxed)),
                )
            });
            // No total body timeout (as the upload agents).
            let config = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build();
            let agent = if production {
                ureq::Agent::with_parts(
                    config,
                    super::idle_layered(paced, idle, FramingConnector(now, false)),
                    DefaultResolver::default(),
                )
            } else {
                ureq::Agent::with_parts(
                    config,
                    paced
                        .chain(FramingConnector(now, false))
                        .chain(IdleConnector(idle)),
                    DefaultResolver::default(),
                )
            };
            // Three TLS-layer writes of body, plus the head.
            let body = vec![7u8; 3 * FRAME];
            let result = agent.put("http://127.0.0.1:9/upload").send(&body[..]);
            (
                result.map(|response| response.status().as_u16()),
                writes.load(Ordering::Relaxed),
                clock.load(Ordering::Relaxed),
            )
        };
        let (moving, writes, elapsed_ms) = send(false, true);
        assert_eq!(moving.unwrap(), 200);
        assert!(writes >= 36, "{writes}");
        assert!(elapsed_ms > 3 * 1000, "{elapsed_ms}");
        let (stopped, writes, _) = send(true, true);
        assert!(
            matches!(stopped, Err(ureq::Error::Timeout(ureq::Timeout::PerWrite))),
            "{stopped:?}"
        );
        assert_eq!(writes, 0);
        // The stand-in is faithful: above it, the bound is an aggregate.
        let (above, writes, _) = send(false, false);
        assert!(
            matches!(above, Err(ureq::Error::Timeout(ureq::Timeout::PerWrite))),
            "{above:?}"
        );
        assert!(writes < 36, "{writes}");
    }

    /// The nested case: an HTTPS CONNECT proxy, so the tunnel carries proxy
    /// TLS below target TLS (both TLS-equivalent `Framing` layers on a fake
    /// clock). `ConnectProxyConnector` runs the chain again for the proxy
    /// connection, so production builds TCP → idle → proxy TLS → CONNECT →
    /// target TLS: a body whose socket writes keep moving past three idle
    /// intervals is sent, one whose socket goes silent mid-body fails
    /// `PerWrite` (stalled). The earlier layering (idle wrapping the tunnel
    /// too, above proxy TLS) fails the moving body, so this test pins it.
    #[test]
    fn idle_bound_wraps_only_the_raw_socket_under_proxy_tls() {
        let idle = Duration::from_secs(1);
        let send = |stop_after: Option<u64>, production: bool| {
            let clock = Arc::new(AtomicU64::new(0));
            let writes = Arc::new(AtomicU64::new(0));
            let paced = PacedConnector {
                clock: clock.clone(),
                step_ms: 400,
                stop_after,
                writes: writes.clone(),
            };
            let started = Instant::now();
            let fake = clock.clone();
            let now: Arc<dyn Fn() -> TransportInstant + Send + Sync> = Arc::new(move || {
                TransportInstant::Exact(
                    started + Duration::from_millis(fake.load(Ordering::Relaxed)),
                )
            });
            let config = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .proxy(Some(ureq::Proxy::new("https://127.0.0.1:3128").unwrap()))
                .build();
            let agent = if production {
                ureq::Agent::with_parts(
                    config,
                    super::idle_layered(paced, idle, FramingConnector(now, false)),
                    DefaultResolver::default(),
                )
            } else {
                ureq::Agent::with_parts(
                    config,
                    ().chain(ConnectProxyConnector::default())
                        .chain(paced)
                        .chain(IdleConnector(idle))
                        .chain(FramingConnector(now, false)),
                    DefaultResolver::default(),
                )
            };
            let body = vec![7u8; 3 * FRAME];
            let result = agent.put("http://127.0.0.1:9/upload").send(&body[..]);
            (
                result.map(|response| response.status().as_u16()),
                writes.load(Ordering::Relaxed),
                clock.load(Ordering::Relaxed),
            )
        };
        let (moving, writes, elapsed_ms) = send(None, true);
        assert_eq!(moving.unwrap(), 200);
        assert!(writes >= 36, "{writes}");
        assert!(elapsed_ms > 3 * 1000, "{elapsed_ms}");
        // Silent after the CONNECT exchange and part of the body.
        let (silent, writes, _) = send(Some(20), true);
        assert!(
            matches!(silent, Err(ureq::Error::Timeout(ureq::Timeout::PerWrite))),
            "{silent:?}"
        );
        assert_eq!(writes, 20);
        let (above, writes, _) = send(None, false);
        assert!(
            matches!(above, Err(ureq::Error::Timeout(ureq::Timeout::PerWrite))),
            "{above:?}"
        );
        assert!(writes < 36, "{writes}");
    }

    /// The response-header budget covers waiting for input only: a layer
    /// that writes while reading the response (a TLS flush) and whose socket
    /// write stalls fails `PerWrite` (stalled) at the write-idle bound, not
    /// at the 300 s response budget.
    #[test]
    fn response_header_wait_keeps_the_write_idle_bound_for_writes() {
        let idle = Duration::from_secs(1);
        let clock = Arc::new(AtomicU64::new(0));
        let writes = Arc::new(AtomicU64::new(0));
        // The head is one socket write; the flush during the read stalls.
        let paced = PacedConnector {
            clock: clock.clone(),
            step_ms: 400,
            stop_after: Some(1),
            writes: writes.clone(),
        };
        let started = Instant::now();
        let fake = clock.clone();
        let now: Arc<dyn Fn() -> TransportInstant + Send + Sync> = Arc::new(move || {
            TransportInstant::Exact(started + Duration::from_millis(fake.load(Ordering::Relaxed)))
        });
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_recv_response(Some(Duration::from_secs(300)))
            .build();
        let agent = ureq::Agent::with_parts(
            config,
            super::idle_layered(paced, idle, FramingConnector(now, true)),
            DefaultResolver::default(),
        );
        let result = agent.get("http://127.0.0.1:9/image").call();
        assert!(
            matches!(result, Err(ureq::Error::Timeout(ureq::Timeout::PerWrite))),
            "{result:?}"
        );
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        assert_eq!(clock.load(Ordering::Relaxed), 400 + 1000);
    }

    /// One socket serving a response: the head at once, then (unless
    /// `stopped`) one body byte per read taking `step_ms` of fake time; a
    /// read whose bound is shorter, or any body read when `stopped`, fails
    /// at its bound.
    #[derive(Debug)]
    struct PacedBody {
        buffers: LazyBuffers,
        clock: Arc<AtomicU64>,
        step_ms: u64,
        stopped: bool,
        head_sent: bool,
        left: usize,
    }

    impl Transport for PacedBody {
        fn buffers(&mut self) -> &mut dyn Buffers {
            &mut self.buffers
        }

        fn transmit_output(&mut self, _: usize, _: NextTimeout) -> Result<(), ureq::Error> {
            Ok(())
        }

        fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
            use ureq::unversioned::transport::time::Duration as Bound;
            if !self.head_sent {
                self.head_sent = true;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    self.left
                );
                self.buffers.input_append_buf()[..head.len()].copy_from_slice(head.as_bytes());
                self.buffers.input_appended(head.len());
                return Ok(true);
            }
            if self.left == 0 {
                return Ok(false);
            }
            let timeout = timeout.for_read();
            let bound = match timeout.after {
                Bound::Exact(bound) => Some(u64::try_from(bound.as_millis()).unwrap()),
                Bound::NotHappening => None,
            };
            if self.stopped || bound.is_some_and(|bound| bound < self.step_ms) {
                let bound = bound.expect("an unbounded stalled read would hang");
                self.clock.fetch_add(bound, Ordering::Relaxed);
                return Err(ureq::Error::Timeout(timeout.reason));
            }
            self.clock.fetch_add(self.step_ms, Ordering::Relaxed);
            self.buffers.input_append_buf()[0] = b'x';
            self.buffers.input_appended(1);
            self.left -= 1;
            Ok(true)
        }

        fn is_open(&mut self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct PacedBodyConnector {
        clock: Arc<AtomicU64>,
        step_ms: u64,
        stopped: bool,
        len: usize,
    }

    impl Connector for PacedBodyConnector {
        type Out = PacedBody;

        fn connect(
            &self,
            _: &ConnectionDetails,
            _: Option<()>,
        ) -> Result<Option<Self::Out>, ureq::Error> {
            Ok(Some(PacedBody {
                buffers: LazyBuffers::new(SOCKET_WRITE, SOCKET_WRITE),
                clock: self.clock.clone(),
                step_ms: self.step_ms,
                stopped: self.stopped,
                head_sent: false,
                left: self.len,
            }))
        }
    }

    /// The read side of the same proof, on the production layering and a
    /// fake clock (no scheduler involved): a response body whose bytes keep
    /// arriving (one per 400 ms) for far more than three idle intervals is
    /// read whole, since there is no total body timeout; one whose bytes stop
    /// fails `PerRead` (stalled) at the bound.
    #[test]
    fn idle_bound_never_fails_a_moving_body_read_and_fails_a_stopped_one() {
        let idle = Duration::from_secs(1);
        let fetch = |stopped: bool| {
            let clock = Arc::new(AtomicU64::new(0));
            let paced = PacedBodyConnector {
                clock: clock.clone(),
                step_ms: 400,
                stopped,
                len: 32,
            };
            let started = Instant::now();
            let fake = clock.clone();
            let now: Arc<dyn Fn() -> TransportInstant + Send + Sync> = Arc::new(move || {
                TransportInstant::Exact(
                    started + Duration::from_millis(fake.load(Ordering::Relaxed)),
                )
            });
            let config = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build();
            let agent = ureq::Agent::with_parts(
                config,
                super::idle_layered(paced, idle, FramingConnector(now, false)),
                DefaultResolver::default(),
            );
            let body = agent
                .get("http://127.0.0.1:9/image")
                .call()
                .and_then(|mut response| response.body_mut().read_to_vec());
            (body, clock.load(Ordering::Relaxed))
        };
        let (moving, elapsed_ms) = fetch(false);
        assert_eq!(moving.unwrap(), vec![b'x'; 32]);
        assert!(elapsed_ms > 12 * 1000, "{elapsed_ms}");
        let (stopped, _) = fetch(true);
        let error = stopped.unwrap_err();
        // read_to_vec surfaces the transport timeout as an io error.
        let timed_out = matches!(error, ureq::Error::Timeout(ureq::Timeout::PerRead))
            || matches!(&error, ureq::Error::Io(io) if io.to_string().contains("timeout"));
        assert!(timed_out, "{error:?}");
    }

    /// A request body the peer stops reading fails after the idle bound with
    /// `PerWrite`, though the agent sets no body timeout. The peer holds its
    /// socket until the client has failed (no race with a peer close).
    #[test]
    fn idle_agent_fails_a_stalled_request_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (failed, held) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = [0u8; 1024];
            let _ = stream.read(&mut head).unwrap();
            // Never read the body; the watchdog only bounds a broken test.
            let _ = held.recv_timeout(Duration::from_secs(60));
            drop(stream);
        });
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();
        let agent = super::idle_agent(config, None, Duration::from_millis(300));
        let body = vec![7u8; 64 << 20];
        let error = agent
            .put(format!("http://{address}/"))
            .send(&body[..])
            .unwrap_err();
        failed.send(()).unwrap();
        assert!(
            matches!(error, ureq::Error::Timeout(ureq::Timeout::PerWrite)),
            "{error:?}"
        );
        server.join().unwrap();
    }

    /// A response body that stalls mid-stream fails after the idle bound
    /// even though the agent sets no total body timeout. The peer holds its
    /// socket until the client has failed. That a moving body never trips
    /// the bound is proven on a fake clock (no scheduler latency):
    /// `idle_bound_never_fails_a_moving_body_read_and_fails_a_stopped_one`.
    #[test]
    fn idle_agent_fails_a_stalled_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (failed, held) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\nab")
                .unwrap();
            // Silent until the client has failed (watchdog only).
            let _ = held.recv_timeout(Duration::from_secs(60));
        });
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();
        let agent = super::idle_agent(config, None, Duration::from_millis(300));
        let mut response = agent.get(format!("http://{address}/")).call().unwrap();
        let stalled = response.body_mut().read_to_vec();
        failed.send(()).unwrap();
        assert!(stalled.is_err(), "a stalled body must fail");
        server.join().unwrap();
    }
}
