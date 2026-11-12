//! ureq exposes either webpki roots or specific DER certificates, but no union.
//! Use its transport API with the same rustls config as WSS to retain both.

use std::io::{Read, Write};
use std::sync::Arc;

use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, DefaultConnector, Either,
    LazyBuffers, NextTimeout, TcpConnector, Transport, TransportAdapter,
};

pub(super) fn agent(config: ureq::config::Config, tls: Arc<rustls::ClientConfig>) -> ureq::Agent {
    ureq::Agent::with_parts(config, tls_connector(tls), DefaultResolver::default())
}

fn tls_connector(tls: Arc<rustls::ClientConfig>) -> impl Connector<Out = impl Transport> {
    ().chain(ConnectProxyConnector::default())
        .chain(TcpConnector::default())
        .chain(TlsConnector(tls))
}

/// An agent whose every read gives up after `idle` without input: ureq's own
/// body timeout is a total budget, so a long streaming download needs this
/// per-read bound to fail a stalled transfer instead of hanging forever.
pub(super) fn idle_read_agent(
    config: ureq::config::Config,
    tls: Option<Arc<rustls::ClientConfig>>,
    idle: std::time::Duration,
) -> ureq::Agent {
    let idle = IdleReadConnector(idle);
    match tls {
        Some(tls) => ureq::Agent::with_parts(
            config,
            tls_connector(tls).chain(idle),
            DefaultResolver::default(),
        ),
        None => ureq::Agent::with_parts(
            config,
            DefaultConnector::new().chain(idle),
            DefaultResolver::default(),
        ),
    }
}

#[derive(Debug)]
struct IdleReadConnector(std::time::Duration);

impl<In: Transport> Connector<In> for IdleReadConnector {
    type Out = IdleRead<In>;

    fn connect(
        &self,
        _details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        Ok(chained.map(|inner| IdleRead {
            inner,
            idle: self.0,
        }))
    }
}

/// Clamps each input wait to the idle bound; writes keep ureq's timeouts.
#[derive(Debug)]
struct IdleRead<T> {
    inner: T,
    idle: std::time::Duration,
}

impl<T: Transport> IdleRead<T> {
    fn clamp(&self, timeout: NextTimeout) -> NextTimeout {
        NextTimeout {
            after: timeout.after.min(self.idle.into()),
            ..timeout
        }
    }
}

impl<T: Transport> Transport for IdleRead<T> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.inner.transmit_output(amount, timeout)
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let timeout = self.clamp(timeout);
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
    fn idle_reads_preserve_stricter_io_and_global_budgets() {
        let idle = IdleRead {
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
        let clamped = idle.clamp(timeout);
        assert_eq!(clamped.after, Duration::from_secs(2).into());
        assert_eq!(clamped.for_read().after, Duration::from_secs(1).into());
        assert_eq!(clamped.for_read().reason, ureq::Timeout::PerRead);
        assert_eq!(clamped.per_write, timeout.per_write);
        let tighter = NextTimeout {
            after: Duration::from_millis(500).into(),
            ..timeout
        };
        assert_eq!(idle.clamp(tighter).for_read().after, tighter.after);
        assert_eq!(idle.clamp(tighter).for_read().reason, ureq::Timeout::Global);
    }

    /// A body that stalls mid-stream fails after the idle bound even though
    /// the agent sets no total body timeout; a steady trickle never trips it.
    #[test]
    fn idle_read_agent_fails_a_stalled_body_but_not_a_slow_one() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // Each connection is served on its own thread, so the stalled one
        // never delays the response to the next request.
        let server = std::thread::spawn(move || {
            let mut workers = Vec::new();
            for trickle in [false, true] {
                let (mut stream, _) = listener.accept().unwrap();
                workers.push(std::thread::spawn(move || {
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nab",
                        )
                        .unwrap();
                    if trickle {
                        for byte in b"cdefgh" {
                            std::thread::sleep(Duration::from_millis(150));
                            stream.write_all(&[*byte]).unwrap();
                        }
                    } else {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();
        let agent = super::idle_read_agent(config, None, Duration::from_millis(500));
        let url = format!("http://{address}/");

        let started = Instant::now();
        let mut response = agent.get(&url).call().unwrap();
        let stalled = response.body_mut().read_to_vec();
        assert!(stalled.is_err(), "a stalled body must fail");
        assert!(started.elapsed() < Duration::from_secs(2));

        let mut response = agent.get(&url).call().unwrap();
        let body = response.body_mut().read_to_vec().unwrap();
        assert_eq!(body, b"abcdefgh");
        server.join().unwrap();
    }
}
