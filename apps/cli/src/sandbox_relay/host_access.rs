//! Session-scoped owner host tools and persisted lowering requests.
use super::{
    agent_policy::AgentPolicy, host_exec::HostExecRegistry, host_files::HostFiles,
    host_policy::HostPolicy,
};
use sandbox_protocol::*;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc;

pub(super) struct HostAccess {
    pub commands: HostExecRegistry,
    pub files: Option<HostFiles>,
    owner: String,
    secret: zeroize::Zeroizing<Vec<u8>>,
    protected: Vec<PathBuf>,
    lower_tx: mpsc::SyncSender<(String, HostPolicyLowerTarget, bool)>,
    lower_rx: mpsc::Receiver<(String, HostPolicyLowerTarget, bool)>,
    lowers: VecDeque<(String, Option<bool>)>,
    replies: Vec<DaemonControlMessage>,
    agent_blocked: bool,
    blocked_enable_revision: Option<u64>,
}
impl HostAccess {
    pub fn new(secret: &str, state: Option<&PathBuf>) -> Self {
        let (lower_tx, lower_rx) = mpsc::sync_channel(64);
        Self {
            commands: HostExecRegistry::new(secret.as_bytes()),
            files: None,
            owner: String::new(),
            secret: zeroize::Zeroizing::new(secret.as_bytes().to_vec()),
            protected: state.cloned().into_iter().collect(),
            lower_tx,
            lower_rx,
            lowers: VecDeque::new(),
            replies: Vec::new(),
            agent_blocked: false,
            blocked_enable_revision: None,
        }
    }
    pub fn register(&mut self, owner: &str, policy: AgentPolicy) -> anyhow::Result<()> {
        self.owner = owner.into();
        self.files = Some(HostFiles::new(
            policy,
            self.owner.clone(),
            &self.secret,
            self.protected.clone(),
        )?);
        Ok(())
    }
    pub fn policy(&self, mut policy: AgentPolicy) -> AgentPolicy {
        if self.agent_blocked {
            policy.enabled = false;
        }
        policy
    }
    pub fn changed(&mut self, policy: AgentPolicy) {
        self.commands.interrupt_all();
        if let Some(files) = &self.files {
            files.update(self.policy(policy));
        }
    }
    pub fn tick(&mut self, policy: &mut HostPolicy) -> bool {
        let mut terminal_changed = false;
        while let Ok((id, target, saved)) = self.lower_rx.try_recv() {
            terminal_changed |= policy.refresh_now();
            let off = match target {
                HostPolicyLowerTarget::HostCommands => !policy.agent().enabled,
                HostPolicyLowerTarget::HostTerminal => !policy.current().enabled,
            };
            let ok = saved && off;
            if target == HostPolicyLowerTarget::HostCommands && ok {
                self.agent_blocked = false;
                self.blocked_enable_revision = None;
            }
            if let Some((_, result)) = self.lowers.iter_mut().find(|(request, _)| *request == id) {
                *result = Some(ok);
            }
            self.replies
                .push(DaemonControlMessage::HostPolicyLowerResult(
                    HostPolicyLowerResultV11 { request_id: id, ok },
                ));
        }
        let witness = policy.agent_enable_revision();
        if self.agent_blocked {
            if self
                .blocked_enable_revision
                .is_some_and(|before| witness > before)
                && policy.agent().enabled
            {
                self.agent_blocked = false;
                self.blocked_enable_revision = None;
            } else {
                self.blocked_enable_revision.get_or_insert(witness);
            }
        }
        terminal_changed
    }
    pub fn lower(
        &mut self,
        req: HostPolicyLowerV11,
        fixture: Option<PathBuf>,
        policy: &mut HostPolicy,
    ) {
        if let Some((_, result)) = self.lowers.iter().find(|(id, _)| *id == req.request_id) {
            if let Some(ok) = result {
                self.replies
                    .push(DaemonControlMessage::HostPolicyLowerResult(
                        HostPolicyLowerResultV11 {
                            request_id: req.request_id,
                            ok: *ok,
                        },
                    ));
            }
            return;
        }
        if self.lowers.len() >= 64 {
            if let Some(at) = self.lowers.iter().position(|(_, done)| done.is_some()) {
                self.lowers.remove(at);
            } else {
                self.replies
                    .push(DaemonControlMessage::HostPolicyLowerResult(
                        HostPolicyLowerResultV11 {
                            request_id: req.request_id,
                            ok: false,
                        },
                    ));
                return;
            }
        }
        if req.target == HostPolicyLowerTarget::HostCommands {
            // The policy latch outlives this connection. Failed persistence
            // must not re-enable commands when a new HostAccess is created.
            policy.block_agent();
            self.agent_blocked = true;
            self.blocked_enable_revision = Some(policy.agent_enable_revision());
            self.commands.interrupt_all();
            if let Some(files) = &self.files {
                files.update(self.policy(policy.agent()));
            }
        }
        self.lowers.push_back((req.request_id.clone(), None));
        let tx = self.lower_tx.clone();
        let id = req.request_id.clone();
        let target = req.target;
        if std::thread::Builder::new()
            .name("wssp-host-policy-lower".into())
            .spawn(move || {
                let deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(2));
                let store = match fixture {
                    Some(dir) => crate::state::AuthStore::at(
                        dir.join("policy-state"),
                        dir.join("config.toml"),
                        deadline,
                    ),
                    None => crate::state::AuthStore::open(deadline),
                };
                let saved = store
                    .and_then(|store| {
                        store.update_config(|c| match target {
                            HostPolicyLowerTarget::HostCommands => c.set_agent_host_commands(false),
                            HostPolicyLowerTarget::HostTerminal => c.set_host_terminal(false),
                        })
                    })
                    .is_ok();
                let _ = tx.try_send((id, target, saved));
            })
            .is_err()
        {
            if let Some((_, result)) = self.lowers.iter_mut().find(|(id, _)| *id == req.request_id)
            {
                *result = Some(false);
            }
            self.replies
                .push(DaemonControlMessage::HostPolicyLowerResult(
                    HostPolicyLowerResultV11 {
                        request_id: req.request_id,
                        ok: false,
                    },
                ));
        }
    }
    pub fn start(&mut self, req: HostExecStartV11, policy: AgentPolicy) -> DaemonControlMessage {
        let policy = self.policy(policy);
        self.commands.start(req, &policy, &self.owner)
    }
    pub fn stdin(&self, req: HostExecStdinV11, policy: AgentPolicy) -> DaemonControlMessage {
        self.commands.stdin(req, &self.policy(policy), &self.owner)
    }
    pub fn replies(&mut self) -> Vec<DaemonControlMessage> {
        let mut frames = std::mem::take(&mut self.replies);
        frames.extend(self.commands.finished());
        if let Some(files) = &mut self.files {
            frames.extend(files.replies());
        }
        frames
    }
    pub fn shutdown(&self) {
        self.commands.interrupt_all();
        if let Some(files) = &self.files {
            files.cancel_pending();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    #[test]
    fn lowering_persists_reloads_kills_and_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = crate::config::Config::default();
        c.set_agent_host_commands(true).unwrap();
        c.set_host_terminal(true).unwrap();
        std::fs::write(&path, toml::to_string(&c).unwrap()).unwrap();
        let mut policy = HostPolicy::new(&c, None, Some(path.clone()));
        let mut access = HostAccess::new("fixture-daemon", Some(&dir.path().to_path_buf()));
        access.register("owner", policy.agent()).unwrap();
        let req = HostExecStartV11 {
            connection_epoch: 1,
            request_id: "start".into(),
            command_id: "abcdefghijklmnopqrstuv".into(),
            owner_id: "owner".into(),
            agent_policy_revision: policy.agent().revision,
            argv: Some(vec!["/bin/sleep".into(), "30".into()]),
            script: None,
            cwd: None,
            timeout_ms: 30000,
            stdin: false,
        };
        assert!(matches!(
            access.start(req, policy.agent()),
            DaemonControlMessage::HostExecStarted(_)
        ));
        for (target, id) in [
            (HostPolicyLowerTarget::HostCommands, "lower-agent"),
            (HostPolicyLowerTarget::HostTerminal, "lower-terminal"),
        ] {
            access.lower(
                HostPolicyLowerV11 {
                    connection_epoch: 1,
                    request_id: id.into(),
                    target,
                },
                Some(dir.path().into()),
                &mut policy,
            );
            let until = Instant::now() + Duration::from_secs(5);
            let mut ack = false;
            while !ack {
                access.tick(&mut policy);
                if policy.take_agent_change() {
                    access.changed(policy.agent());
                }
                for reply in access.replies() {
                    if let DaemonControlMessage::HostPolicyLowerResult(r) = reply
                        && r.request_id == id
                    {
                        assert!(r.ok);
                        ack = true;
                    }
                }
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let saved = crate::config::Config::read(&path).unwrap();
        assert!(!saved.allow_agent_host_commands);
        assert!(!saved.allow_host_terminal);
        let revision = saved.agent_policy_revision;
        access.lower(
            HostPolicyLowerV11 {
                connection_epoch: 1,
                request_id: "lower-agent".into(),
                target: HostPolicyLowerTarget::HostCommands,
            },
            Some(dir.path().into()),
            &mut policy,
        );
        assert!(
            access
                .replies()
                .iter()
                .any(|r| matches!(r,DaemonControlMessage::HostPolicyLowerResult(r) if r.ok))
        );
        assert_eq!(
            crate::config::Config::read(&path)
                .unwrap()
                .agent_policy_revision,
            revision
        );
        let until = Instant::now() + Duration::from_secs(4);
        loop {
            let DaemonControlMessage::HostExecStatus(s) =
                access
                    .commands
                    .poll("abcdefghijklmnopqrstuv", None, 0, 0, 0)
            else {
                panic!()
            };
            if s.state != HostExecState::Running {
                assert_eq!(s.state, HostExecState::Interrupted);
                break;
            }
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(test)]
mod failed_lower_tests {
    use super::*;
    #[test]
    fn host_failed_persistence_stays_off_across_connections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = crate::config::Config::default();
        c.set_agent_host_commands(true).unwrap();
        std::fs::write(&path, toml::to_string(&c).unwrap()).unwrap();
        let mut policy = HostPolicy::new(&c, None, Some(path.clone()));
        let broken = tempfile::tempdir().unwrap();
        // A directory in place of a config file makes persistence fail even
        // when tests run with a UID that ignores ordinary write permissions.
        std::fs::create_dir(broken.path().join("config.toml")).unwrap();
        let mut access = HostAccess::new("fixture", None);
        access.lower(
            HostPolicyLowerV11 {
                connection_epoch: 1,
                request_id: "fails".into(),
                target: HostPolicyLowerTarget::HostCommands,
            },
            Some(broken.path().into()),
            &mut policy,
        );
        assert!(!policy.agent().enabled);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            access.tick(&mut policy);
            if let Some(reply) = access.replies().into_iter().find_map(|r| match r {
                DaemonControlMessage::HostPolicyLowerResult(r) => Some(r),
                _ => None,
            }) {
                assert!(!reply.ok);
                break;
            }
            assert!(std::time::Instant::now() < until);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(access.agent_blocked);
        assert!(
            crate::config::Config::read(&path)
                .unwrap()
                .allow_agent_host_commands
        );
        drop(access);
        let reconnected = HostAccess::new("fixture", None);
        policy.refresh_now();
        assert!(!reconnected.policy(policy.agent()).enabled);
        c.set_agent_host_commands(true).unwrap();
        std::fs::write(&path, toml::to_string(&c).unwrap()).unwrap();
        policy.refresh_now();
        assert!(reconnected.policy(policy.agent()).enabled);
    }
    #[test]
    fn host_lower_failure_stays_blocked_until_successful_lower_or_local_enable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = crate::config::Config::default();
        c.set_agent_host_commands(true).unwrap();
        std::fs::write(&path, toml::to_string(&c).unwrap()).unwrap();
        let mut p = HostPolicy::new(&c, None, Some(path.clone()));
        let mut a = HostAccess::new("fixture", None);
        a.agent_blocked = true;
        a.blocked_enable_revision = Some(p.agent_enable_revision());
        for (saved, enabled) in [(false, true), (true, true), (false, false)] {
            c.allow_agent_host_commands = enabled;
            std::fs::write(&path, toml::to_string(&c).unwrap()).unwrap();
            a.lower_tx
                .send(("failed".into(), HostPolicyLowerTarget::HostCommands, saved))
                .unwrap();
            a.tick(&mut p);
            assert!(!a.policy(p.agent()).enabled);
            assert!(a.agent_blocked);
        }
        a.lower_tx
            .send((
                "saved-off".into(),
                HostPolicyLowerTarget::HostCommands,
                true,
            ))
            .unwrap();
        a.tick(&mut p);
        assert!(!a.agent_blocked);
        // Fail another lowering while enabled, then allow a genuine local enable.
        c.set_agent_host_commands(true).unwrap();
        std::fs::write(&path, toml::to_string(&c).unwrap()).unwrap();
        p.refresh_now();
        a.agent_blocked = true;
        a.blocked_enable_revision = Some(p.agent_enable_revision());
        a.lower_tx
            .send((
                "failed-again".into(),
                HostPolicyLowerTarget::HostCommands,
                false,
            ))
            .unwrap();
        a.tick(&mut p);
        assert!(a.agent_blocked);
        c.set_agent_host_commands(true).unwrap();
        std::fs::write(&path, toml::to_string(&c).unwrap()).unwrap();
        p.refresh_now();
        a.tick(&mut p);
        assert!(!a.agent_blocked);
        assert!(a.policy(p.agent()).enabled);
    }
}
