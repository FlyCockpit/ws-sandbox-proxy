//! Mutation outcomes. `Ok(value)` is positive completion; failures carry evidence,
//! never a code-based guess. `?` on an ordinary observation ALWAYS becomes Unknown.
use crate::RuntimeError;
use sandbox_protocol::OperationState;

/// The live claim is for a running VM. Create requires absence; reconnect
/// may retain a stopped disk, provided this first attempt never issued a start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationKind {
    Create,
    Reconnect,
}
impl AllocationKind {
    /// The allocation kind of a dispatch, not of its
    /// kind string. A `sandbox.reconnect` carrying `restore` boots a new root
    /// from a stored disk, so it is released only on create proofs (root
    /// absence plus first-attempt evidence); a partial root stays unknown.
    pub fn from_dispatch(dispatch: &sandbox_protocol::OperationDispatch) -> Option<Self> {
        Self::from_launch(
            &dispatch.kind,
            dispatch
                .restore
                .as_ref()
                .map(|_| sandbox_protocol::LaunchMode::NewRoot)
                .or(dispatch.launch_mode),
        )
    }

    /// The same mapping from a journaled receipt's kind and launch mode
    /// (restart recovery and allocation attestation).
    pub fn from_launch(
        kind: &str,
        launch_mode: Option<sandbox_protocol::LaunchMode>,
    ) -> Option<Self> {
        match (kind, launch_mode) {
            ("sandbox.create", _) => Some(Self::Create),
            ("sandbox.reconnect", Some(sandbox_protocol::LaunchMode::NewRoot)) => {
                Some(Self::Create)
            }
            ("sandbox.reconnect", _) => Some(Self::Reconnect),
            _ => None,
        }
    }
}

/// C-26: a release needs first-attempt evidence and a negative observation
/// appropriate to the allocation kind. An observation error cannot release.
pub fn allocation_refusal_state(
    first_attempt: bool,
    possibly_live: Option<bool>,
) -> OperationState {
    if first_attempt && possibly_live == Some(false) {
        OperationState::Failed
    } else {
        OperationState::UnknownOutcome
    }
}

/// Observe the runtime before releasing a refused allocation. Pure validation
/// cannot rule out a live VM left by an earlier host process.
pub fn allocation_refusal_for_runtime(
    runtime: &dyn crate::SandboxRuntime,
    kind: AllocationKind,
    first_attempt: bool,
    sandbox_id: &str,
) -> OperationState {
    if !first_attempt {
        return OperationState::UnknownOutcome;
    }
    let possibly_live = match kind {
        AllocationKind::Create => runtime.sandbox_exists(sandbox_id),
        AllocationKind::Reconnect => runtime.sandbox_may_be_running(sandbox_id),
    };
    allocation_refusal_state(first_attempt, possibly_live.ok())
}

/// A plain response cannot claim a mutation completed.
/// ```compile_fail
/// fn unproven() -> sandbox_runtime::EffectOutcome<()> { Ok(()) }
/// ```
/// Raw errors cannot claim that an effect was not issued.
/// ```compile_fail
/// use sandbox_runtime::{EffectOutcome, RuntimeError};
/// use sandbox_protocol::SandboxErrorCode;
/// fn unproven() -> EffectOutcome<()> {
///     Err(RuntimeError::new(SandboxErrorCode::HostEffectNotIssued, "no proof"))
/// }
/// ```
pub type EffectOutcome<T> = Result<Completed<T>, EffectError>;
/// Intermediate IO/validation observations are not completion evidence.
#[cfg(target_os = "linux")]
pub(crate) type EffectResult<T> = Result<T, EffectError>;

// Only the enumerated evidence sources can implement this trait. The seal is
// private even to sibling modules within this crate.
mod sealed {
    pub trait Sealed {}
    impl<T> Sealed for crate::fake::SimulatedCompletion<T> {}
    impl Sealed for crate::reconcile::InventoryProof {}
    #[cfg(target_os = "linux")]
    impl<T> Sealed for crate::incus::effect_completion::ObservedCompletion<T> {}
    #[cfg(target_os = "linux")]
    impl Sealed for crate::incus::exec::LocalControlCompletion {}
    #[cfg(target_os = "linux")]
    impl Sealed for crate::incus::exec::CancelledCompletion {}
}
pub(crate) trait PositiveEvidence: sealed::Sealed + Sized {
    type Value;
    fn value(self) -> Self::Value;
    fn complete(self) -> Completed<Self::Value> {
        Completed::new(self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed<T> {
    value: T,
}
impl<T> Completed<T> {
    fn new(proof: impl PositiveEvidence<Value = T>) -> Self {
        Self {
            value: proof.value(),
        }
    }
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> Completed<U> {
        Completed {
            value: map(self.value),
        }
    }
    pub fn into_value(self) -> T {
        self.value
    }
    /// Chain another mutation after positive evidence. Any failure of the next
    /// substep is uncertainty about this composite, even if that substep never spawned.
    pub fn then<U>(self, next: impl FnOnce(T) -> EffectOutcome<U>) -> EffectOutcome<U> {
        next(self.value).map_err(EffectError::after_issue)
    }
    pub fn observe(
        self,
        observation: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> EffectOutcome<T> {
        observation().map_err(EffectError::from)?;
        Ok(self)
    }
}
impl<T> std::ops::Deref for Completed<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectError {
    NotIssued(crate::before_issue::NotIssuedProof),
    Completed(CompletionFailure),
    Unknown(Observation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    error: RuntimeError,
    command: Option<Box<crate::RunCommandResponse>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionFailure {
    Simulated(crate::fake::SimulatedFailure),
    #[cfg(target_os = "linux")]
    Guest(crate::incus::effect_completion::GuestFailure),
    /// The daemon refused `incus start` and the bound instance was then
    /// observed Stopped (see `effect_completion::running`).
    #[cfg(target_os = "linux")]
    StartRefused(crate::incus::effect_completion::StartRefusal),
    /// E-19: the command outlived its `timeoutMs`, and the supervisor's own
    /// stop is proven to have ended it (see `exec::CommandTimedOut`).
    #[cfg(target_os = "linux")]
    CommandTimedOut(crate::incus::exec::CommandTimedOut),
}
impl CompletionFailure {
    fn error(&self) -> &RuntimeError {
        match self {
            Self::Simulated(proof) => proof.error(),
            #[cfg(target_os = "linux")]
            Self::Guest(proof) => proof.error(),
            #[cfg(target_os = "linux")]
            Self::StartRefused(proof) => proof.error(),
            #[cfg(target_os = "linux")]
            Self::CommandTimedOut(proof) => proof.error(),
        }
    }
}

impl EffectError {
    /// Apply the same create-refusal rule used by the relay before runtime issue.
    pub fn for_create(self, first_attempt: bool, instance_exists: Option<bool>) -> Self {
        if allocation_refusal_state(first_attempt, instance_exists) == OperationState::Failed {
            self
        } else {
            self.after_issue()
        }
    }
    /// Uncertainty about a possibly issued mutation always overrides a nested
    /// errno's effect. A precise errno never supplies rollback evidence.
    pub fn failure(&self) -> Option<sandbox_protocol::results::Failure> {
        let mut failure = std::ops::Deref::deref(self).failure()?.clone();
        if matches!(self, Self::Unknown(_)) {
            failure.effect = sandbox_protocol::results::FailureEffect::Unknown;
        }
        Some(failure)
    }
    pub fn state(&self) -> OperationState {
        match self {
            Self::NotIssued(_) | Self::Completed(_) => OperationState::Failed,
            Self::Unknown(_) => OperationState::UnknownOutcome,
        }
    }
    /// A subsequent phase cannot retroactively prove an earlier mutation unissued.
    pub fn after_issue(self) -> Self {
        Self::Unknown(self.into())
    }
    pub fn into_error(self) -> RuntimeError {
        match self {
            Self::NotIssued(p) => p.into_error(),
            Self::Completed(p) => p.error().clone(),
            Self::Unknown(e) => e.error.uncertain(),
        }
    }
    pub fn command(&self) -> Option<&crate::RunCommandResponse> {
        match self {
            Self::Unknown(observation) => observation.command.as_deref(),
            #[cfg(target_os = "linux")]
            Self::Completed(CompletionFailure::CommandTimedOut(proof)) => Some(proof.response()),
            _ => None,
        }
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn unknown_command(command: crate::RunCommandResponse) -> Self {
        Self::Unknown(Observation {
            error: RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::UnknownOutcome,
                "command has no completion evidence",
            ),
            command: Some(Box::new(command)),
        })
    }
}
impl From<RuntimeError> for EffectError {
    fn from(error: RuntimeError) -> Self {
        Self::Unknown(Observation {
            error: error.uncertain(),
            command: None,
        })
    }
}
impl std::ops::Deref for EffectError {
    type Target = RuntimeError;
    fn deref(&self) -> &RuntimeError {
        match self {
            Self::NotIssued(p) => p.error(),
            Self::Completed(p) => p.error(),
            Self::Unknown(e) => &e.error,
        }
    }
}
impl std::fmt::Display for EffectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&**self, f)
    }
}
impl std::error::Error for EffectError {}

/// Post-issue code cannot return a NotIssued variant. Even a nested adapter's
/// pre-issue proof becomes an observation about the already-issued parent.
#[derive(Debug)]
pub(crate) enum PostIssueError {
    #[cfg(target_os = "linux")]
    Completed(CompletionFailure),
    Unknown(Observation),
}
#[cfg(target_os = "linux")]
pub(crate) type PostIssueOutcome<T> = Result<Completed<T>, PostIssueError>;
impl From<RuntimeError> for Observation {
    fn from(error: RuntimeError) -> Self {
        Self {
            error: error.uncertain(),
            command: None,
        }
    }
}
impl From<EffectError> for Observation {
    fn from(error: EffectError) -> Self {
        match error {
            EffectError::Unknown(observation) => observation,
            other => other.into_error().into(),
        }
    }
}
impl From<RuntimeError> for PostIssueError {
    fn from(error: RuntimeError) -> Self {
        Self::Unknown(error.into())
    }
}
impl From<EffectError> for PostIssueError {
    fn from(error: EffectError) -> Self {
        Self::Unknown(error.into())
    }
}
#[cfg(target_os = "linux")]
impl Observation {
    /// Interim/unknown command observations repeat the bound start identity.
    pub(crate) fn with_birth(mut self, birth: Option<crate::CommandBirth>) -> Self {
        if let Some(command) = &mut self.command {
            command.command.birth = birth;
        }
        self
    }
}
#[cfg(target_os = "linux")]
impl PostIssueError {
    /// Attach the bound start identity to any command observation it carries.
    pub(crate) fn with_birth(self, birth: Option<crate::CommandBirth>) -> Self {
        match self {
            Self::Unknown(observation) => Self::Unknown(observation.with_birth(birth)),
            Self::Completed(CompletionFailure::CommandTimedOut(mut proof)) => {
                proof.set_birth(birth);
                Self::Completed(CompletionFailure::CommandTimedOut(proof))
            }
            other => other,
        }
    }
    /// A composite whose FINAL mutation is `incus start`: a start refusal
    /// keeps its completed-failure evidence (the daemon refused and the VM
    /// was observed Stopped afterwards, so nothing of the composite can
    /// still be running). Every other nested failure stays uncertainty
    /// about the composite, exactly like `From<EffectError>`.
    pub(crate) fn from_final_start(error: EffectError) -> Self {
        match error {
            EffectError::Completed(CompletionFailure::StartRefused(proof)) => {
                Self::Completed(CompletionFailure::StartRefused(proof))
            }
            other => other.into(),
        }
    }
}
impl From<PostIssueError> for EffectError {
    fn from(error: PostIssueError) -> Self {
        match error {
            #[cfg(target_os = "linux")]
            PostIssueError::Completed(proof) => Self::Completed(proof),
            PostIssueError::Unknown(observation) => Self::Unknown(observation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn later_precondition_cannot_retroactively_make_parent_not_issued() {
        let outcome = crate::before_issue::phase(
            |before| before.issue(|| Ok(())),
            |()| {
                crate::before_issue::phase(
                    |before| {
                        crate::before_issue::incus::path(&before, "/", true)?;
                        before.issue(|| Ok(()))
                    },
                    Ok,
                )?;
                Ok(())
            },
        );
        assert_eq!(outcome.unwrap_err().state(), OperationState::UnknownOutcome);
    }

    #[test]
    fn every_raw_error_code_is_unknown_in_post_issue_code() {
        for code in sandbox_protocol::SandboxErrorCode::ALL {
            let raw = RuntimeError::new(*code, "post-issue observation");
            let outcome: EffectError = PostIssueError::from(raw).into();
            assert_eq!(outcome.state(), OperationState::UnknownOutcome, "{code}");
        }
    }
    #[test]
    fn post_issue_errno_cannot_claim_rollback() {
        let raw = crate::metadata::fs_error(sandbox_protocol::SandboxErrorCode::FsNotFound);
        assert_eq!(
            raw.failure().unwrap().effect,
            sandbox_protocol::results::FailureEffect::None
        );
        let uncertain = EffectError::from(raw);
        assert_eq!(uncertain.state(), OperationState::UnknownOutcome);
        assert_eq!(
            uncertain.failure().unwrap().effect,
            sandbox_protocol::results::FailureEffect::Unknown
        );
        assert_eq!(
            uncertain.into_error().failure().unwrap().effect,
            sandbox_protocol::results::FailureEffect::Unknown
        );
    }
}
