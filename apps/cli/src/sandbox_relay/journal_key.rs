//! A key lives only for the current authenticated relay session, never on disk.
use std::sync::Arc;

use anyhow::{Result, bail};
use ring::hmac;
use sandbox_protocol::JournalKeyInstall;

use super::journal::{HostJournal, TransportBindingV11};

/// Handles private installs both during reconciliation and in the dispatch loop.
#[derive(Clone, Copy)]
pub(super) struct KeyControl<'a> {
    pub journal: &'a HostJournal,
    pub binding: &'a TransportBindingV11,
    pub epoch: Option<u64>,
    /// During reconciliation the server may already offer its credential
    /// return key (hello step §4.3.0); it is applied here and its ack waits
    /// in the credential outbox until reconciliation completes.
    pub credentials: Option<&'a super::credentials::service::CredentialService>,
}

impl KeyControl<'_> {
    pub fn parse(
        self,
        text: &str,
        socket: &mut tungstenite::WebSocket<
            tungstenite::stream::MaybeTlsStream<std::net::TcpStream>,
        >,
    ) -> Result<Option<sandbox_protocol::ServerControlMessage>> {
        use sandbox_protocol::{DaemonControlMessage, ServerControlMessage};
        let message = match sandbox_protocol::parse_server_control(text) {
            Ok(message) => message,
            Err(error) => {
                // Recognize rejected install frames without bypassing protocol
                // validation or logging their payload. Keep decoding bounded.
                if text.len() <= sandbox_protocol::json_control_max_bytes()
                    && let Ok(frame) = serde_json::from_str::<serde_json::Value>(text)
                {
                    match frame.get("type").and_then(|v| v.as_str()) {
                        Some("journal.key.install") => {
                            self.reject();
                            return Ok(None);
                        }
                        Some("private.config.install") => {
                            self.reject_config();
                            return Ok(None);
                        }
                        _ => {}
                    }
                }
                return Err(error.into());
            }
        };
        if let ServerControlMessage::ReceiptPrunedAck(ack) = &message {
            if let Some(epoch) = self.epoch {
                self.journal.acknowledge_pruned(self.binding, epoch, ack)?;
            }
            return Ok(None);
        }
        if let (ServerControlMessage::CredentialReturnKey(_), Some(credentials)) =
            (&message, self.credentials)
        {
            if self.epoch.is_some() {
                credentials.handle_server(message);
            }
            return Ok(None);
        }
        if let ServerControlMessage::PrivateConfigInstall(frame) = &message {
            let Some(epoch) = self.epoch else {
                self.reject_config();
                return Ok(None);
            };
            if let Some(response) = self.config_response(frame, epoch) {
                socket.send(tungstenite::Message::Text(
                    super::plain_frame(&response)?.into(),
                ))?;
            }
            return Ok(None);
        }
        let ServerControlMessage::JournalKeyInstall(frame) = message else {
            return Ok(Some(message));
        };
        let Some(epoch) = self.epoch else {
            self.reject();
            return Ok(None);
        };
        if self
            .journal
            .install_key(&frame, self.binding, epoch)
            .is_err()
        {
            self.reject();
            return Ok(None);
        }
        socket.send(tungstenite::Message::Text(
            super::plain_frame(&DaemonControlMessage::JournalKeyAck {
                connection_epoch: epoch,
                key_version: frame.key_version,
                key_id: frame.key_id,
            })?
            .into(),
        ))?;
        Ok(None)
    }

    pub(super) fn config_response(
        self,
        frame: &sandbox_protocol::PrivateConfigInstall,
        epoch: u64,
    ) -> Option<sandbox_protocol::DaemonControlMessage> {
        use sandbox_protocol::{
            DaemonControlMessage, PrivateConfigRefusalReason, PrivateConfigRefused,
        };
        match self.journal.install_config(frame, self.binding, epoch) {
            Ok(ack) => Some(DaemonControlMessage::PrivateConfigAck(ack)),
            Err(error) => {
                // Post-persist errors and invalid bindings never prove no effect.
                let response = match (
                    &frame.refusal_token,
                    error.downcast_ref::<PrivateConfigRefusalReason>(),
                ) {
                    (Some(token), Some(reason)) => Some(
                        DaemonControlMessage::PrivateConfigRefused(PrivateConfigRefused {
                            sandbox_owner_id: frame.sandbox_owner_id.clone(),
                            connection_epoch: epoch,
                            sandbox_id: frame.sandbox_id.clone(),
                            generation: frame.generation,
                            config_id: frame.config.config_id.clone(),
                            refusal_token: token.clone(),
                            reason: *reason,
                        }),
                    ),
                    _ => None,
                };
                if error
                    .downcast_ref::<super::journal::ConfigInstallIo>()
                    .is_some()
                {
                    tracing::warn!("private config journal IO failed; config refused");
                } else {
                    self.reject_config();
                }
                response
            }
        }
    }

    fn reject_config(self) {
        tracing::warn!("invalid private config binding or install; config refused");
    }

    fn reject(self) {
        self.journal.clear_key();
        // Origins are not secrets, but omit them too: one constant class is
        // sufficient to diagnose a canonical-origin or other binding mismatch.
        tracing::warn!("invalid journal key binding or install; keyed work unavailable");
    }
}

pub(super) struct MemoryJournalKey {
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

/// The session's journal key lifetime. Work carried across a relay drop may
/// still need the key (an admitted create's lease acceptance digests its
/// dispatch), so a session that ends with pending work keeps the key until
/// the next session's install replaces it, or a revoking exit clears it
/// (live finding B-3). Otherwise the key is cleared at both ends, as before.
pub(super) struct KeySession {
    journal: Arc<HostJournal>,
    carried: Option<super::authority::HostAuthority>,
}
impl KeySession {
    #[cfg(test)]
    pub fn start(journal: Arc<HostJournal>) -> Self {
        journal.clear_key();
        Self {
            journal,
            carried: None,
        }
    }
    pub fn start_carrying(
        journal: Arc<HostJournal>,
        authority: super::authority::HostAuthority,
    ) -> Self {
        if !authority.has_pending() {
            journal.clear_key();
        }
        Self {
            journal,
            carried: Some(authority),
        }
    }
}
impl Drop for KeySession {
    fn drop(&mut self) {
        if !self.carried.as_ref().is_some_and(|a| a.has_pending()) {
            self.journal.clear_key();
        }
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
