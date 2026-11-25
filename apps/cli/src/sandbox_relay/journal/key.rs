//! The in-memory journal key of the current relay session: installed from a
//! `journal.key.install` frame bound to this host, never written to disk, and
//! used for the journal's keyed digests (`mac`).
use anyhow::{Result, bail};
use ring::hmac;
use sandbox_protocol::JournalKeyInstall;

use super::TransportBindingV11;

pub(in crate::sandbox_relay) struct MemoryJournalKey {
    pub key_id: String,
    pub binding: TransportBindingV11,
    pub key: hmac::Key,
    #[cfg(test)]
    pub mac_calls: std::sync::atomic::AtomicUsize,
}
impl std::fmt::Debug for MemoryJournalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryJournalKey([REDACTED])")
    }
}
impl MemoryJournalKey {
    pub fn install(
        frame: &JournalKeyInstall,
        binding: &TransportBindingV11,
        epoch: u64,
    ) -> Result<Self> {
        if !frame.is_valid()
            || frame.connection_epoch != epoch
            || frame.server != binding.server
            || frame.host_owner_id != binding.host_owner_id
            || frame.host_id != binding.host_id
        {
            bail!("invalid journal key binding");
        }
        let mut bytes = [0_u8; 32];
        for (slot, pair) in bytes
            .iter_mut()
            .zip(frame.key_hex.as_bytes().as_chunks::<2>().0.iter())
        {
            let hex = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => 0,
            };
            *slot = (hex(pair[0]) << 4) | hex(pair[1]);
        }
        Ok(Self {
            #[cfg(test)]
            mac_calls: std::sync::atomic::AtomicUsize::new(0),
            key_id: frame.key_id.clone(),
            binding: binding.clone(),
            key: hmac::Key::new(hmac::HMAC_SHA256, &bytes),
        })
    }
    pub fn mac(&self, domain: &str, payload: &str) -> String {
        #[cfg(test)]
        self.mac_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut bytes = Vec::new();
        for field in [
            domain,
            &self.key_id,
            &self.binding.server,
            &self.binding.host_owner_id,
            &self.binding.host_id,
            payload,
        ] {
            // All callers provide bounded protocol fields and bounded JSON control frames.
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        hmac::sign(&self.key, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_mac_is_deterministic_and_domain_and_binding_separated() {
        let binding = TransportBindingV11 {
            server: "wss://server/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let frame = JournalKeyInstall {
            connection_epoch: 1,
            key_version: 1,
            key_id: "d".repeat(32),
            key_hex: "ab".repeat(32),
            server: binding.server.clone(),
            host_owner_id: binding.host_owner_id.clone(),
            host_id: binding.host_id.clone(),
        };
        let key = MemoryJournalKey::install(&frame, &binding, 1).unwrap();
        let first = key.mac("dispatch", "private");
        assert_eq!(
            first,
            "a590dd4d0294b9de9ee852b80be1e31119e5823ca5623fc9e94be905a348a40d"
        );
        assert_eq!(first, key.mac("dispatch", "private"));
        assert_ne!(first, key.mac("config", "private"));
        let next_binding = TransportBindingV11 {
            host_id: "other".into(),
            ..binding
        };
        let next_frame = JournalKeyInstall {
            host_id: "other".into(),
            ..frame
        };
        let other = MemoryJournalKey::install(&next_frame, &next_binding, 1).unwrap();
        assert_ne!(first, other.mac("dispatch", "private"));
    }
}
