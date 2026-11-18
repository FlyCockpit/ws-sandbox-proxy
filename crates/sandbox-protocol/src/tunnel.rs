//! Optional preview tunnels: the node daemon runs a
//! pinned `tunnel` client per sandbox, outside the guest, forwarding only the
//! sandbox's declared ports. The control plane owns the tunnel on the tunnel
//! server and hands the host one short-lived per-tunnel token per apply.

use serde::{Deserialize, Serialize};

/// Most ports one sandbox may declare (`network.tunnelPorts`).
pub const TUNNEL_MAX_PORTS: usize = 8;
/// Upper bound on a tunnel server origin carried in `tunnel.apply`.
pub const TUNNEL_SERVER_MAX_BYTES: usize = 256;
/// Upper bound on a per-tunnel token carried in `tunnel.apply`.
pub const TUNNEL_TOKEN_MAX_BYTES: usize = 128;
/// Upper bound on a tunnel id a host reports.
pub const TUNNEL_ID_MAX_BYTES: usize = 64;

/// Exposed tunnel ports: 1..=8 distinct non-zero ports in ascending order
/// (one encoding per set, so receipts and plans compare exactly).
pub fn valid_tunnel_ports(ports: &[u16]) -> bool {
    !ports.is_empty() && valid_declared_tunnel_ports(ports)
}

/// A tunnel sandbox's declared ports: like [`valid_tunnel_ports`], but may
/// be empty (a tunnel sandbox that declared none yet: its guest address is
/// pinned, no port is admitted).
pub fn valid_declared_tunnel_ports(ports: &[u16]) -> bool {
    ports.len() <= TUNNEL_MAX_PORTS
        && ports.iter().all(|port| *port != 0)
        && ports.windows(2).all(|pair| pair[0] < pair[1])
}

/// `https://host[:port]` with nothing else: no path, query, userinfo or
/// whitespace. The host's client dials only this origin.
pub fn valid_tunnel_server(server: &str) -> bool {
    let Some(rest) = server.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && server.len() <= TUNNEL_SERVER_MAX_BYTES
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        && !rest.starts_with(['.', '-', ':'])
}

/// A per-tunnel token: `tntun_` and base64url, nothing that could be read
/// as another credential kind.
pub fn valid_tunnel_token(token: &str) -> bool {
    token.len() <= TUNNEL_TOKEN_MAX_BYTES
        && token.strip_prefix("tntun_").is_some_and(|body| {
            body.len() >= 16
                && body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
}

fn valid_tunnel_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= TUNNEL_ID_MAX_BYTES
        && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn valid_generation(generation: u64) -> bool {
    generation > 0 && generation <= 9_007_199_254_740_991
}

/// Hello capability: the node has a hash-verified client installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelCapabilityV11 {
    /// SHA-256 (lowercase hex) of the pinned client binary.
    pub client_sha256: String,
    /// Most tunnel clients this node runs at once.
    pub max_tunnels: u32,
    /// Node owner consent: other users' sandboxes may use tunnels here.
    pub allow_for_others: bool,
}

impl TunnelCapabilityV11 {
    pub fn is_valid(&self) -> bool {
        self.client_sha256.len() == 64
            && self
                .client_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (1..=256).contains(&self.max_tunnels)
    }
}

/// Server → host: run (or replace) this sandbox's tunnel client. The token
/// is held only in memory and in the client's tmpfs state directory.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelApplyV11 {
    pub sandbox_id: String,
    /// Strictly increases per sandbox; an apply at or below the current one
    /// is stale and ignored.
    pub generation: u64,
    pub server: String,
    pub token: String,
    /// The ports to expose: a subset of the sandbox's declared ports.
    pub ports: Vec<u16>,
}

impl std::fmt::Debug for TunnelApplyV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelApplyV11")
            .field("sandbox_id", &self.sandbox_id)
            .field("generation", &self.generation)
            .field("server", &self.server)
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

impl TunnelApplyV11 {
    pub fn is_valid(&self) -> bool {
        crate::valid_inventory_sandbox_id(&self.sandbox_id)
            && valid_generation(self.generation)
            && valid_tunnel_server(&self.server)
            && valid_tunnel_token(&self.token)
            && valid_tunnel_ports(&self.ports)
    }
}

/// Server → host: stop this sandbox's client (any generation up to this one).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelClearV11 {
    pub sandbox_id: String,
    pub generation: u64,
}

impl TunnelClearV11 {
    pub fn is_valid(&self) -> bool {
        crate::valid_inventory_sandbox_id(&self.sandbox_id) && valid_generation(self.generation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStateV11 {
    Connecting,
    Connected,
    /// The client is not running (cleared, or never started).
    Stopped,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelErrorV11 {
    /// The tunnel was deleted or expired, or its token was refused (exit 3).
    TunnelGone,
    /// Another client connected with a newer token (exit 4).
    Replaced,
    /// The client kept failing; the host stopped restarting it.
    ClientFailed,
    /// The host refused the apply: no capability, a hash mismatch, ports the
    /// sandbox's recorded plan does not carry, or the node's tunnel limit.
    Refused,
}

/// Host → server: the client state for one generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelStatusV11 {
    pub sandbox_id: String,
    pub generation: u64,
    pub state: TunnelStateV11,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<TunnelErrorV11>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_id: Option<String>,
}

impl TunnelStatusV11 {
    pub fn is_valid(&self) -> bool {
        crate::valid_inventory_sandbox_id(&self.sandbox_id)
            && valid_generation(self.generation)
            && (self.state == TunnelStateV11::Error) == self.error.is_some()
            && self.tunnel_id.as_deref().is_none_or(valid_tunnel_id)
    }
}

/// Server → host: the sandbox's declared tunnel ports changed at runtime.
/// The host replaces its recorded plan's tunnel rule (and stops a client
/// forwarding a port no longer declared) only for a revision above the one
/// it recorded; the guest has no channel that reaches this.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelPortsV11 {
    pub sandbox_id: String,
    /// Strictly increases per sandbox (`Sandbox.tunnelPortsRevision`).
    pub revision: u64,
    /// The full declared set (0-8, ascending).
    pub ports: Vec<u16>,
}

impl TunnelPortsV11 {
    pub fn is_valid(&self) -> bool {
        crate::valid_inventory_sandbox_id(&self.sandbox_id)
            && valid_generation(self.revision)
            && valid_declared_tunnel_ports(&self.ports)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelPortsOutcomeV11 {
    /// The recorded plan carries `revision` (or a newer one).
    Applied,
    /// No recorded plan for the sandbox on this host (not materialized, or
    /// torn down): the next launch's dispatch carries the ports.
    Absent,
    /// Not a tunnel sandbox here (no pinned guest address), or not a
    /// runtime that records tunnel plans.
    Refused,
    /// Not applied now (busy, an uncertain ACL write, a host error): retry.
    Failed,
}

/// Host → server: the outcome of a `tunnel.ports`. For `applied`,
/// `revision` is the revision the recorded plan now carries (at least the
/// requested one); otherwise the requested one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelPortsStatusV11 {
    pub sandbox_id: String,
    pub revision: u64,
    pub outcome: TunnelPortsOutcomeV11,
}

impl TunnelPortsStatusV11 {
    pub fn is_valid(&self) -> bool {
        crate::valid_inventory_sandbox_id(&self.sandbox_id) && valid_generation(self.revision)
    }
}

/// `tunnelPorts` on a launch dispatch: present exactly for a tunnel sandbox
/// (possibly empty: pinned, nothing admitted yet).
pub(crate) fn deserialize_tunnel_ports<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u16>>, D::Error> {
    let ports = Vec::<u16>::deserialize(deserializer)?;
    if valid_declared_tunnel_ports(&ports) {
        Ok(Some(ports))
    } else {
        Err(serde::de::Error::custom(
            "tunnel ports must be 0-8 distinct ascending non-zero ports",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_have_one_encoding() {
        assert!(valid_tunnel_ports(&[3000]));
        assert!(valid_tunnel_ports(&[80, 3000, 5173]));
        assert!(!valid_tunnel_ports(&[]));
        assert!(!valid_tunnel_ports(&[0]));
        assert!(!valid_tunnel_ports(&[3000, 3000]));
        assert!(!valid_tunnel_ports(&[5173, 3000]));
        assert!(!valid_tunnel_ports(&[1, 2, 3, 4, 5, 6, 7, 8, 9]));
        // Declared sets may be empty; nothing else differs.
        assert!(valid_declared_tunnel_ports(&[]));
        assert!(valid_declared_tunnel_ports(&[3000]));
        assert!(!valid_declared_tunnel_ports(&[0]));
        assert!(!valid_declared_tunnel_ports(&[5173, 3000]));
        assert!(!valid_declared_tunnel_ports(&[1, 2, 3, 4, 5, 6, 7, 8, 9]));
    }

    #[test]
    fn ports_frames_validate() {
        let mut frame = TunnelPortsV11 {
            sandbox_id: "sbx".into(),
            revision: 1,
            ports: vec![],
        };
        assert!(frame.is_valid());
        frame.ports = vec![3000, 5173];
        assert!(frame.is_valid());
        frame.revision = 0;
        assert!(!frame.is_valid());
        frame.revision = 2;
        frame.ports = vec![5173, 3000];
        assert!(!frame.is_valid());
        let status = TunnelPortsStatusV11 {
            sandbox_id: "sbx".into(),
            revision: 2,
            outcome: TunnelPortsOutcomeV11::Applied,
        };
        assert!(status.is_valid());
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({"sandboxId": "sbx", "revision": 2, "outcome": "applied"})
        );
    }

    #[test]
    fn server_is_a_bare_https_origin() {
        assert!(valid_tunnel_server("https://tunnel.example.com"));
        assert!(valid_tunnel_server("https://tunnel.example.com:8443"));
        for bad in [
            "http://tunnel.example.com",
            "https://",
            "https://tunnel.example.com/",
            "https://user@tunnel.example.com",
            "https://tunnel.example.com?x",
            "https://tunnel example.com",
            "wss://tunnel.example.com",
        ] {
            assert!(!valid_tunnel_server(bad), "{bad}");
        }
    }

    #[test]
    fn token_is_a_tunnel_token() {
        assert!(valid_tunnel_token(
            "tntun_abcdefghijklmnopqrstuvwxyz012345-_"
        ));
        assert!(!valid_tunnel_token(
            "tncli_abcdefghijklmnopqrstuvwxyz012345"
        ));
        assert!(!valid_tunnel_token("tntun_short"));
        assert!(!valid_tunnel_token("tntun_abcdefghijklmnop\nqrstuv"));
    }

    #[test]
    fn apply_debug_never_prints_the_token() {
        let apply = TunnelApplyV11 {
            sandbox_id: "sbx".into(),
            generation: 1,
            server: "https://tunnel.example.com".into(),
            token: "tntun_secretsecretsecretsecret".into(),
            ports: vec![3000],
        };
        assert!(!format!("{apply:?}").contains("tntun_"));
    }

    #[test]
    fn status_error_pairs_with_state() {
        let mut status = TunnelStatusV11 {
            sandbox_id: "sbx".into(),
            generation: 1,
            state: TunnelStateV11::Connected,
            error: None,
            tunnel_id: Some("abc123".into()),
        };
        assert!(status.is_valid());
        status.error = Some(TunnelErrorV11::Replaced);
        assert!(!status.is_valid());
        status.state = TunnelStateV11::Error;
        assert!(status.is_valid());
        status.tunnel_id = Some("a/b".into());
        assert!(!status.is_valid());
    }
}
