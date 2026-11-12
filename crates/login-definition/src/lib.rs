//! wssp CLI login definition v1, shared byte for byte with
//! `packages/login-definition` (`@wssp/login-definition`): validation,
//! canonical JSON digest, constructed header values and the bundle v1 codec.
//! Conformance vectors live in `packages/login-definition/vectors/` and are
//! consumed by both test suites.

pub mod bundle;
pub mod canonical;
pub mod definition;
pub mod limits;
pub mod net;
pub mod paths;
pub mod secret;

pub use bundle::{
    Bundle, BundleEnv, BundleError, BundleErrorReason, BundleFile, BundleFileKind, decode_bundle,
    encode_bundle, missing_required_paths, serialize_bundle_unchecked,
};
pub use canonical::{CanonicalJsonError, canonical_json, definition_digest};
pub use definition::{
    DefinitionError, DefinitionErrorCode, DefinitionWarning, LoginDefinition, ParsedDefinition,
    load_verified_definition, parse_definition, parse_definition_str,
};
pub use net::{HeaderValueError, ValidatedHeaderValue, env_value_acceptable};
pub use secret::SecretBuf;
