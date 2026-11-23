//! A loopback TCP proxy that delays every byte by a fixed one-way time in
//! each direction, the way a WAN path between the CLI and the server does,
//! for throughput tests of the connect plane. It buffers no more than
//! [`PIPE_BYTES`] per direction (it stops reading beyond), so the flow
//! control under test is the only thing that bounds what is in flight.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Bytes in flight per direction at most (a path's bandwidth-delay product
/// far above any window the tests use).
pub const PIPE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct Pipe {
    state: Mutex<PipeState>,
    changed: Condvar,
}

#[derive(Default)]
struct PipeState {
    queue: VecDeque<(Instant, Vec<u8>)>,
    bytes: usize,
    eof: bool,
}

/// One direction: `from` is read as soon as there is room, every chunk is
/// written to `to` `delay` after it was read.
fn relay(mut from: TcpStream, mut to: TcpStream, delay: Duration) {
    let pipe = Arc::new(Pipe::default());
    let reader = {
        let pipe = pipe.clone();
        thread::spawn(move || {
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                {
                    let mut state = pipe.state.lock().unwrap();
                    while state.bytes >= PIPE_BYTES {
                        state = pipe.changed.wait(state).unwrap();
                    }
                }
                let n = from.read(&mut buffer).unwrap_or(0);
                let mut state = pipe.state.lock().unwrap();
                if n == 0 {
                    state.eof = true;
                    pipe.changed.notify_all();
                    return;
                }
                state.bytes += n;
                state
                    .queue
                    .push_back((Instant::now() + delay, buffer[..n].to_vec()));
                pipe.changed.notify_all();
            }
        })
    };
    loop {
        let (due, bytes) = {
            let mut state = pipe.state.lock().unwrap();
            loop {
                if let Some(front) = state.queue.pop_front() {
                    state.bytes -= front.1.len();
                    pipe.changed.notify_all();
                    break front;
                }
                if state.eof {
                    let _ = to.shutdown(Shutdown::Write);
                    let _ = reader.join();
                    return;
                }
                state = pipe.changed.wait(state).unwrap();
            }
        };
        let now = Instant::now();
        if due > now {
            thread::sleep(due - now);
        }
        if to.write_all(&bytes).is_err() {
            let _ = to.shutdown(Shutdown::Both);
            return;
        }
    }
}

/// A proxy to `upstream` (`host:port`) on a loopback port of its own.
pub struct Latency {
    pub address: String,
    stop: Arc<AtomicBool>,
}

impl Latency {
    /// Every connection to [`Latency::address`] reaches `upstream` with
    /// `one_way` added in each direction.
    pub fn start(upstream: &str, one_way: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let upstream = upstream.to_owned();
        {
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let client = match listener.accept() {
                        Ok((client, _)) => client,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => return,
                    };
                    client.set_nonblocking(false).unwrap();
                    let Ok(server) = TcpStream::connect(&upstream) else {
                        continue;
                    };
                    for stream in [&client, &server] {
                        stream.set_nodelay(true).unwrap();
                    }
                    let (c2, s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                    thread::spawn(move || relay(client, server, one_way));
                    thread::spawn(move || relay(s2, c2, one_way));
                }
            });
        }
        Self { address, stop }
    }
}

impl Drop for Latency {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}
