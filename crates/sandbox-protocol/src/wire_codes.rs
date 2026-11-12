//! Strict 1.0 daemon encoding. Every precise error retains its catalog spelling.
use crate::control::{ControlError, DaemonControlMessage, encode_daemon_control};
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SpelledFrame {
    pub text: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireCodes {
    valid: bool,
}
impl WireCodes {
    pub const CURRENT: Self = Self { valid: true };
    pub fn negotiated(version: &str) -> Self {
        Self {
            valid: crate::known_protocol_version(version),
        }
    }
    pub fn valid(self) -> bool {
        self.valid
    }
    pub fn dispatch_size(
        self,
        dispatch: &crate::OperationDispatch,
    ) -> Result<Option<crate::VmSize>, ControlError> {
        if !self.valid {
            return Err(ControlError::InvalidAdmission);
        }
        crate::dispatch_vm_size(dispatch, crate::SANDBOX_RELAY_PROTOCOL_VERSION)
    }
    pub fn encode(
        self,
        message: &DaemonControlMessage,
        _kind: Option<&str>,
    ) -> Result<SpelledFrame, ControlError> {
        if !self.valid {
            return Err(ControlError::InvalidAdmission);
        }
        Ok(SpelledFrame {
            text: encode_daemon_control(message)?,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_old_encoders() {
        for v in ["10.0", "10.5", "10.7", "11.1"] {
            assert!(
                WireCodes::negotiated(v)
                    .encode(
                        &DaemonControlMessage::ReconcileComplete {
                            pending_receipts: None
                        },
                        None
                    )
                    .is_err()
            );
        }
        assert!(
            WireCodes::negotiated("1.0")
                .encode(
                    &DaemonControlMessage::ReconcileComplete {
                        pending_receipts: None
                    },
                    None
                )
                .is_ok()
        );
    }

    fn receipt_with(
        code: crate::WireErrorCode,
        reason: Option<crate::ProtocolErrorReason>,
    ) -> DaemonControlMessage {
        let mut message =
            crate::parse_daemon_control(include_str!("../fixtures/control_operation_receipt.json"))
                .expect("fixture");
        if let DaemonControlMessage::OperationReceipt { state, error, .. } = &mut message {
            *state = crate::OperationState::Failed;
            *error = Some(crate::ProtocolErrorDetail {
                reason,
                code,
                message: "newer".into(),
                operation_id: None,
                sandbox_id: None,
            });
        }
        message
    }

    #[test]
    fn other_codes_encode_verbatim_and_only_when_canonical() {
        use crate::WireErrorCode;
        let wire = WireCodes::CURRENT;
        let frame = wire
            .encode(
                &receipt_with(WireErrorCode::Other("future_code".into()), None),
                None,
            )
            .expect("valid Other encodes");
        assert!(frame.text.contains(r#""code":"future_code""#));
        match crate::parse_daemon_control(&frame.text).expect("decodes") {
            DaemonControlMessage::OperationReceipt {
                error: Some(error), ..
            } => assert_eq!(error.code, WireErrorCode::Other("future_code".into())),
            message => panic!("unexpected {message:?}"),
        }
        for bad in ["Bad-Code", "", "timeout"] {
            assert!(
                wire.encode(&receipt_with(WireErrorCode::Other(bad.into()), None), None)
                    .is_err(),
                "{bad}"
            );
        }
        // A typed reason never pairs with an Other code.
        let reason = crate::ProtocolErrorReason::Capacity(crate::capacity_v11::CapacityReason::Ram);
        assert!(!reason.fits_wire(&WireErrorCode::Other("host_capacity_v".into())));
        assert!(reason.fits_wire(&crate::SandboxErrorCode::HostCapacity.into()));
        assert!(
            wire.encode(
                &receipt_with(WireErrorCode::Other("future_code".into()), Some(reason)),
                None
            )
            .is_err()
        );
        assert!(
            wire.encode(
                &receipt_with(crate::SandboxErrorCode::HostCapacity.into(), Some(reason)),
                None
            )
            .is_ok()
        );
    }
}
