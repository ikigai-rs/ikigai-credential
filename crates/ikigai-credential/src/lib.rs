//! Verifiable credentials as ikigai resources.
//!
//! This crate issues and verifies W3C Verifiable Credentials 2.0 in the Open Badges 3.0 profile,
//! secured with Data Integrity `eddsa-rdfc-2022`: the document and the proof configuration are
//! canonicalized with RDFC-1.0 (ikigai-rdf), each hashed with SHA-256, the two hashes are
//! concatenated (proof configuration first), the 64 bytes are signed with Ed25519, and the
//! signature is encoded base58-btc multibase (ikigai-sign). Contexts come from ikigai-jsonld's
//! pinned, offline loader, and documents are read in JSON-LD safe mode.
//!
//! This is the cryptosuite core. The `urn:credential:*` resources in the README's map are built
//! on it. Every name lives under [`NAMESPACE`].
#![forbid(unsafe_code)]

mod canon;
pub mod resource;

use ed25519_dalek::{Signature, VerifyingKey};
use ikigai_sign::multikey::{multibase_decode, multibase_encode};
use oxsdatatypes::DateTime;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// The prefix every name in this module starts with.
///
/// ```
/// assert_eq!(ikigai_credential::NAMESPACE, "urn:credential:");
/// assert!("urn:credential:issuer:name:example".starts_with(ikigai_credential::NAMESPACE));
/// ```
pub const NAMESPACE: &str = "urn:credential:";

/// The one cryptosuite this crate issues and verifies.
pub const CRYPTOSUITE: &str = "eddsa-rdfc-2022";

/// The largest request body [`verify`] reads, in bytes.
pub const MAX_INPUT_BYTES: usize = 1 << 20;

/// Why a document could not be issued or checked. Each carries one sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input is not a document this crate accepts.
    Input(String),
    /// Canonicalization refused or failed.
    Canonicalize(String),
    /// The signer refused or failed.
    Sign(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Input(s) | Error::Canonicalize(s) | Error::Sign(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

/// Parse request bytes as JSON, bounding size and nesting depth BEFORE any parser recurses.
pub fn parse_bounded(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::Input(format!(
            "The document is larger than {MAX_INPUT_BYTES} bytes; send a smaller document."
        )));
    }
    ikigai_jsonld::check_json_nesting(bytes, "credential")
        .map_err(|e| Error::Input(e.to_string()))?;
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Input(format!("The document is not valid JSON: {e}.")))
}

/// Something that signs the 64-byte `eddsa-rdfc-2022` message with an issuer's Ed25519 key.
///
/// The key stays where the signer keeps it (ikigai-secret, through ikigai-sign); this crate
/// only asks for a signature, which is the raw 64-byte Ed25519 signature.
pub trait Signer {
    /// Sign `message` and return the Ed25519 signature.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

/// The proof options an issuer chooses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOptions {
    /// The `created` date-time, an XML Schema `dateTime` (for example `2026-11-27T00:00:00Z`).
    pub created: String,
    /// The verification method's URL, for example `did:web:example.org#key-1`.
    pub verification_method: String,
    /// The proof purpose; `assertionMethod` for a credential.
    pub proof_purpose: String,
}

/// Canonical N-Quads of a JSON-LD document, offline and in safe mode.
pub fn canonicalize(document: &Value) -> Result<String, Error> {
    canon::canonical_nquads(document)
}

/// SHA-256 of the canonical proof configuration, then SHA-256 of the canonical document.
pub fn hash_data(canonical_proof_config: &str, canonical_document: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&Sha256::digest(canonical_proof_config.as_bytes()));
    out[32..].copy_from_slice(&Sha256::digest(canonical_document.as_bytes()));
    out
}

fn proof_config(document: &Map<String, Value>, proof: &Map<String, Value>) -> Value {
    let mut config = proof.clone();
    config.remove("proofValue");
    if let Some(context) = document.get("@context") {
        config.insert("@context".into(), context.clone());
    }
    Value::Object(config)
}

fn hash_for(document: &Map<String, Value>, proof: &Map<String, Value>) -> Result<[u8; 64], Error> {
    let config = canonicalize(&proof_config(document, proof))?;
    let doc = canonicalize(&Value::Object(document.clone()))?;
    Ok(hash_data(&config, &doc))
}

/// Secure `unsecured` with an `eddsa-rdfc-2022` proof, signed by `signer`.
///
/// Refuses a document that already carries a proof, and a document whose graph has a blank
/// node: everything this crate emits is skolemized.
pub fn issue(
    unsecured: &Value,
    options: &ProofOptions,
    signer: &impl Signer,
) -> Result<Value, Error> {
    let prepared = prepare(unsecured, options)?;
    let signature = signer.sign(&prepared.message).map_err(Error::Sign)?;
    Ok(prepared.secure(&signature))
}

/// An unsecured credential checked and hashed for signing: the 64 bytes to sign, and the
/// document and proof the signature completes.
pub(crate) struct Prepared {
    document: Map<String, Value>,
    proof: Map<String, Value>,
    pub(crate) message: [u8; 64],
}

impl Prepared {
    /// The secured credential: the proof, with the signature as base58-btc multibase.
    pub(crate) fn secure(mut self, signature: &[u8; 64]) -> Value {
        self.proof
            .insert("proofValue".into(), multibase_encode(signature).into());
        self.document
            .insert("proof".into(), Value::Object(self.proof));
        Value::Object(self.document)
    }
}

/// Check `unsecured` and compute the `eddsa-rdfc-2022` message for it, before any signer is
/// asked: [`issue`] signs in process, the issue resource asks ikigai-sign through the kernel.
pub(crate) fn prepare(unsecured: &Value, options: &ProofOptions) -> Result<Prepared, Error> {
    let Value::Object(document) = unsecured else {
        return Err(Error::Input("The credential must be a JSON object.".into()));
    };
    if document.contains_key("proof") {
        return Err(Error::Input(
            "The credential already has a proof; issue an unsecured credential.".into(),
        ));
    }
    if canonicalize(unsecured)?.contains("_:") {
        return Err(Error::Input(
            "The credential has a node without an id; give every node an id before issuing.".into(),
        ));
    }
    let mut proof = Map::new();
    proof.insert("type".into(), "DataIntegrityProof".into());
    proof.insert("cryptosuite".into(), CRYPTOSUITE.into());
    proof.insert("created".into(), options.created.clone().into());
    proof.insert(
        "verificationMethod".into(),
        options.verification_method.clone().into(),
    );
    proof.insert("proofPurpose".into(), options.proof_purpose.clone().into());
    let message = hash_for(document, &proof)?;
    Ok(Prepared {
        document: document.clone(),
        proof,
        message,
    })
}

/// What verification found. [`Verdict::sentence`] says it in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The proof checks out against the issuer's key, and the credential is in its validity window.
    Valid,
    /// The credential does not verify, for the reason given.
    Invalid(String),
}

impl Verdict {
    /// One sentence that says what was checked and what was found.
    pub fn sentence(&self) -> String {
        match self {
            Verdict::Valid => "The credential is valid: its eddsa-rdfc-2022 proof matches the issuer's key, and it is within its validity period.".into(),
            Verdict::Invalid(why) => format!("The credential is not valid: {why}"),
        }
    }
}

/// Verify a secured credential's `eddsa-rdfc-2022` proof.
///
/// `bytes` is the request body: its size and nesting are bounded before it is parsed.
/// `key_as_of(verification_method, valid_from)` returns the issuer's public key that was current
/// at `validFrom` (from the key history), or a sentence saying why there is none. `now` is the
/// verifier's clock as an `xsd:dateTimeStamp` (for example `2026-11-27T12:00:00Z` or
/// `2026-11-27T14:00:00.5+02:00`); a clock with no timezone is refused. `validFrom` and
/// `validUntil` are `xsd:dateTimeStamp`s too, as VC 2.0 types them: fractional seconds and any
/// offset are accepted, the bounds are compared as instants and both are inclusive, and a value
/// with no timezone makes the verdict invalid with a sentence saying so. Status is not read
/// here.
pub fn verify(
    bytes: &[u8],
    now: &str,
    key_as_of: impl Fn(&str, Option<&str>) -> Result<VerifyingKey, String>,
) -> Result<Verdict, Error> {
    let Value::Object(mut document) = parse_bounded(bytes)? else {
        return Err(Error::Input("The credential must be a JSON object.".into()));
    };
    let now =
        parse_stamp(now).map_err(|e| Error::Input(e.sentence("The verifier's clock", now)))?;
    let invalid = |s: &str| Ok(Verdict::Invalid(s.to_owned()));
    let Some(Value::Object(proof)) = document.remove("proof") else {
        return invalid("it has no single proof object.");
    };
    let text = |key: &str| proof.get(key).and_then(Value::as_str);
    if text("type") != Some("DataIntegrityProof") || text("cryptosuite") != Some(CRYPTOSUITE) {
        return invalid(
            "its proof is not a DataIntegrityProof with the eddsa-rdfc-2022 cryptosuite.",
        );
    }
    if text("proofPurpose") != Some("assertionMethod") {
        return invalid("its proof purpose is not assertionMethod.");
    }
    let Some(method) = text("verificationMethod") else {
        return invalid("its proof names no verification method.");
    };
    let Some(signature) = text("proofValue")
        .and_then(|v| multibase_decode(v).ok())
        .and_then(|b| Signature::from_slice(&b).ok())
    else {
        return invalid("its proof value is not a base58-btc multibase Ed25519 signature.");
    };
    let valid_from = match date_time_stamp(&document, "validFrom") {
        Ok(found) => found,
        Err(why) => return Ok(Verdict::Invalid(why)),
    };
    let valid_until = match date_time_stamp(&document, "validUntil") {
        Ok(found) => found,
        Err(why) => return Ok(Verdict::Invalid(why)),
    };
    let key = match key_as_of(method, valid_from.map(|(text, _)| text)) {
        Ok(key) => key,
        Err(why) => return Ok(Verdict::Invalid(why)),
    };
    let message = hash_for(&document, &proof)?;
    if key.verify_strict(&message, &signature).is_err() {
        return invalid("its proof does not match the issuer's key, so it was changed after signing or signed by another key.");
    }
    if let Some((_, from)) = valid_from {
        if now < from {
            return invalid("its validity period has not started yet.");
        }
    }
    if let Some((_, until)) = valid_until {
        if until < now {
            return invalid("its validity period has ended.");
        }
    }
    Ok(Verdict::Valid)
}

/// Parse an `xsd:dateTimeStamp`: an XML Schema `dateTime` that carries a timezone (`Z` or an
/// offset), with optional fractional seconds. Parsing is oxsdatatypes', the XSD implementation
/// oxrdf and oxigraph use; two stamps then compare as instants, whatever their offsets.
fn parse_stamp(text: &str) -> Result<DateTime, StampError> {
    let parsed = DateTime::from_str(text).map_err(|_| StampError::NotAStamp)?;
    if parsed.timezone_offset().is_none() {
        return Err(StampError::NoTimezone);
    }
    Ok(parsed)
}

enum StampError {
    NotAStamp,
    NoTimezone,
}

impl StampError {
    fn sentence(&self, what: &str, text: &str) -> String {
        match self {
            StampError::NoTimezone => format!(
                "{what} {text:?} has no timezone; a date-time stamp needs Z or an offset such as +02:00."
            ),
            StampError::NotAStamp => format!(
                "{what} {text:?} is not a date-time stamp such as 2026-11-01T00:00:00Z."
            ),
        }
    }
}

/// The credential's `key` as text and as an instant, if present; a sentence if it is malformed.
fn date_time_stamp<'a>(
    document: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<(&'a str, DateTime)>, String> {
    match document.get(key) {
        None => Ok(None),
        Some(Value::String(text)) => parse_stamp(text)
            .map(|at| Some((text.as_str(), at)))
            .map_err(|e| e.sentence(&format!("its {key}"), text)),
        Some(other) => {
            Err(StampError::NotAStamp.sentence(&format!("its {key}"), &other.to_string()))
        }
    }
}
