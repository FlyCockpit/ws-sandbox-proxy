//! Shared test-only child ownership. Every asynchronous CLI spawn goes here.
use std::io::{self, Read};
use std::process::{Child, Command, Output};

pub struct ManagedChild(Child);

impl ManagedChild {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command.spawn().map(Self)
    }

    // Keep ownership while draining pipes and waiting, including on panic.
    #[allow(dead_code)] // Some integration binaries only need wait/try_wait.
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        let stdout = self.stdout.take();
        let stderr = self.stderr.take();
        self.stdin.take();
        std::thread::scope(|scope| {
            let drain = |pipe: Option<_>| -> io::Result<Vec<u8>> {
                let mut bytes = Vec::new();
                if let Some(mut pipe) = pipe {
                    Read::read_to_end(&mut pipe, &mut bytes)?;
                }
                Ok(bytes)
            };
            let out = scope.spawn(move || drain(stdout));
            let err = scope.spawn(move || {
                let mut bytes = Vec::new();
                if let Some(mut pipe) = stderr {
                    pipe.read_to_end(&mut bytes)?;
                }
                Ok::<_, io::Error>(bytes)
            });
            let status = self.wait();
            // Reap/kill before joining readers: an exited leader may leave a
            // descendant holding its pipe open, and a failed wait still owns
            // a live child. Neither should strand the output collectors.
            self.terminate();
            Ok(Output {
                status: status?,
                stdout: out.join().expect("stdout reader panicked")?,
                stderr: err.join().expect("stderr reader panicked")?,
            })
        })
    }
}

impl std::ops::Deref for ManagedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for ManagedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl ManagedChild {
    fn terminate(&mut self) {
        #[cfg(unix)]
        {
            // Descendants may outlive an already-exited leader. Always clean
            // the private group created by spawn, never the runner's group.
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", self.0.id())])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.terminate();
    }
}
