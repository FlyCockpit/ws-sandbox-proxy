//! Live, fail-closed agent access policy; only a setter's enable witness unlatches.
use crate::config::Config;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AgentPolicy {
    pub enabled: bool,
    pub max_ms: u64,
    pub roots: Vec<PathBuf>,
    pub revision: u64,
}
impl AgentPolicy {
    pub fn authorize(
        &self,
        revision: u64,
        owner: &str,
        host_owner: &str,
    ) -> Result<(), sandbox_protocol::HostExecRejectReason> {
        use sandbox_protocol::HostExecRejectReason as R;
        if !self.enabled {
            return Err(R::HostCommandsOff);
        }
        if revision != self.revision {
            return Err(R::PolicyChanged);
        }
        if owner.is_empty() || owner != host_owner {
            return Err(R::OwnerMismatch);
        }
        Ok(())
    }
    pub fn report(&self, epoch: u32, sequence: u64) -> sandbox_protocol::HostAgentPolicyV11 {
        sandbox_protocol::HostAgentPolicyV11 {
            connection_epoch: epoch,
            sequence,
            host_commands: self.enabled,
            host_files: self.enabled && !self.roots.is_empty(),
            host_command_max_ms: self.enabled.then_some(self.max_ms),
            agent_policy_revision: self.revision,
        }
    }
}
pub(super) struct AgentLatch {
    pub policy: AgentPolicy,
    saved: (bool, u64, Vec<PathBuf>, u64, u64),
    latched: bool,
    changed: bool,
}
fn tuple(c: &Config) -> (bool, u64, Vec<PathBuf>, u64, u64) {
    (
        c.allow_agent_host_commands,
        c.host_command_max_ms,
        c.host_file_roots.clone(),
        c.agent_policy_revision,
        c.agent_policy_enable_revision,
    )
}
impl AgentLatch {
    pub fn new(c: &Config) -> Self {
        let enabled = c.allow_agent_host_commands && c.validate_agent_policy().is_ok();
        Self {
            policy: AgentPolicy {
                enabled,
                max_ms: c.host_command_max_ms,
                roots: c.host_file_roots.clone(),
                revision: c.agent_policy_revision,
            },
            saved: tuple(c),
            latched: !enabled,
            changed: false,
        }
    }
    pub fn enable_revision(&self) -> u64 {
        self.saved.4
    }
    pub fn take_change(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }
    pub fn block(&mut self) {
        if !self.latched || self.policy.enabled {
            self.latched = true;
            self.policy.enabled = false;
            self.advance();
        }
    }
    pub fn refresh(&mut self, config: Option<&Config>) {
        let Some(c) = config.filter(|c| c.validate_agent_policy().is_ok()) else {
            self.block();
            return;
        };
        let next = tuple(c);
        if self.saved == next {
            return;
        }
        let witnessed = next.4 > self.saved.4;
        if witnessed && next.0 {
            self.latched = false;
        }
        if !next.0 {
            self.latched = true;
        }
        self.saved = next;
        self.policy.enabled = self.saved.0 && !self.latched;
        self.policy.max_ms = if witnessed {
            self.saved.1
        } else {
            self.policy.max_ms.min(self.saved.1)
        };
        if witnessed {
            self.policy.roots = self.saved.2.clone();
        } else {
            self.policy.roots.retain(|p| self.saved.2.contains(p));
        }
        self.advance();
    }
    fn advance(&mut self) {
        if self.policy.revision >= sandbox_protocol::HOST_SAFE_INTEGER - 1 {
            self.policy.enabled = false;
            self.latched = true;
        } else {
            self.policy.revision = (self.policy.revision + 1)
                .max(self.saved.3)
                .min(sandbox_protocol::HOST_SAFE_INTEGER);
        }
        self.changed = true;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn off_and_failure_need_a_new_enable_witness() {
        let mut c = Config::default();
        let mut l = AgentLatch::new(&c);
        c.allow_agent_host_commands = true;
        l.refresh(Some(&c));
        assert!(!l.policy.enabled);
        c.set_agent_host_commands(true).unwrap();
        l.refresh(Some(&c));
        assert!(l.policy.enabled);
        l.refresh(None);
        assert!(!l.policy.enabled);
        l.refresh(Some(&c));
        assert!(!l.policy.enabled);
        c.set_agent_host_commands(true).unwrap();
        l.refresh(Some(&c));
        assert!(l.policy.enabled);
        c.set_agent_host_commands(false).unwrap();
        l.refresh(Some(&c));
        assert!(!l.policy.enabled);
        c.allow_agent_host_commands = true;
        l.refresh(Some(&c));
        assert!(!l.policy.enabled);
        assert!(l.take_change());
        assert!(!l.take_change());
    }
    #[test]
    fn authorizes_revision_and_connection_owner() {
        use sandbox_protocol::HostExecRejectReason as R;
        let mut l = AgentLatch::new(&Config::default());
        assert_eq!(l.policy.authorize(0, "a", "a"), Err(R::HostCommandsOff));
        l.policy.enabled = true;
        assert_eq!(l.policy.authorize(1, "a", "a"), Err(R::PolicyChanged));
        assert_eq!(l.policy.authorize(0, "b", "a"), Err(R::OwnerMismatch));
        assert_eq!(l.policy.authorize(0, "a", "a"), Ok(()));
    }
}

#[cfg(test)]
mod widening_tests {
    use super::*;
    #[test]
    fn host_limits_and_roots_only_widen_with_a_setter_witness() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let mut c = Config::default();
        c.set_agent_host_commands(true).unwrap();
        c.set_host_file_roots(&[a.path().into()]).unwrap();
        let mut latch = AgentLatch::new(&c);
        c.host_command_max_ms *= 2;
        c.host_file_roots.push(b.path().into());
        c.agent_policy_revision += 1;
        latch.refresh(Some(&c));
        assert_eq!(latch.policy.max_ms, 600_000);
        assert_eq!(latch.policy.roots, vec![a.path().to_path_buf()]);
        // A revision alone, and repeating the edit, never legitimizes a raise.
        c.agent_policy_revision += 1;
        latch.refresh(Some(&c));
        assert_eq!(latch.policy.max_ms, 600_000);
        assert_eq!(latch.policy.roots, vec![a.path().to_path_buf()]);
        c.host_command_max_ms = 1000;
        c.host_file_roots = vec![b.path().into()];
        latch.refresh(Some(&c));
        assert_eq!(latch.policy.max_ms, 1000);
        assert!(
            latch.policy.roots.is_empty(),
            "removal applies, unwitnessed addition does not"
        );
        c.set_host_command_max_ms(2000).unwrap();
        latch.refresh(Some(&c));
        assert_eq!(latch.policy.max_ms, 2000);
        assert_eq!(latch.policy.roots, vec![b.path().to_path_buf()]);
        c.set_host_file_roots(&[a.path().into(), b.path().into()])
            .unwrap();
        latch.refresh(Some(&c));
        assert_eq!(latch.policy.roots.len(), 2);
        c.set_host_file_roots(&[]).unwrap();
        c.set_host_command_max_ms(1000).unwrap();
        latch.refresh(Some(&c));
        assert!(latch.policy.roots.is_empty());
        assert_eq!(latch.policy.max_ms, 1000);
    }
}
