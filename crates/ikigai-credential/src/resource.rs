//! The `urn:credential:*` resources: the issuer, the achievement, the credential atom, the
//! sealed issue Sink and the open verifier, bound by [`space`].
//!
//! | Name | Verb | Requires |
//! |---|---|---|
//! | `urn:credential:issuer:name:{i}` | Source | nothing: an issuer's profile is public |
//! | `urn:credential:achievement:course:{c}:release:{r}` | Source | nothing: composed from the release's description, read through the kernel |
//! | `urn:credential:id:{id}` | Source | [`CAP_READ`]: whether a credential is shown is its holder's choice, not this module's |
//! | `urn:credential:issue:enrollment:{n}` | Sink | [`CAP_ISSUE`], ikigai-sign's `urn:cap:sign` and ikigai-log's [`CAP_LOG_WRITE`], plus whatever the host says its issuers' keys need |
//! | `urn:credential:verify` | Source | nothing: verification is public |
//!
//! The issue Sink is sealed by state: it answers `Conflict` unless the enrollment's completion
//! rule holds, and once an enrollment has its credential it answers `Conflict` naming it. It
//! signs through the kernel: the 64-byte `eddsa-rdfc-2022` message goes to ikigai-sign's
//! `urn:sign:sign` with the issuer's key IRI (a resource in ikigai-secret), so the key never
//! enters this module. The credential it writes is an atom: written once, never changed. Each
//! issuance then writes one ikigai-log entry through `urn:log:write` ([`ISSUANCE_CLASS`], about
//! the credential's public IRI, with the enrollment and the issuer; ikigai-log attributes it to
//! the caller's principal), and never the subject's email, hash or did:key.
//!
//! The credential's public IRI comes from the host's per-issuer template, expanded here:
//! ikigai-name 0.9.0 resolves and administers namespaces but has no resource that mints a single
//! IRI. The status list is ledger #4146.

use crate::{parse_bounded, parse_stamp, prepare, ProofOptions, Verdict};
use async_trait::async_trait;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use ikigai_core::{
    ArgRef, ArgSpec, Bindings, Description, Endpoint, EndpointSpace, Error as CoreError,
    FailureClass, InputGroup, Invocation, Iri, ReprType, Representation, Request,
    Result as CoreResult, UriTemplate, Verb, PRINCIPAL_SCOPE_PREFIX,
};
use ikigai_sign::multikey::{did_key_resolve, multikey_decode, DID_KEY_PREFIX};
use oxsdatatypes::{DateTime, DayTimeDuration};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

/// The capability that may issue a credential (the issue Sink).
pub const CAP_ISSUE: &str = "urn:cap:credential:issue";

/// The capability that may read an issued credential atom.
pub const CAP_READ: &str = "urn:cap:credential:read";

/// ikigai-sign's signing capability, which the issue Sink's sub-request to `urn:sign:sign` runs
/// under.
pub const CAP_SIGN: &str = ikigai_sign::CAP_SIGN;

/// ikigai-sign's signing resource.
pub const SIGN: &str = "urn:sign:sign";

/// ikigai-log's append point, where the issue Sink writes one entry per issuance.
pub const LOG_WRITE: &str = "urn:log:write";

/// ikigai-log's capability to append an entry, which the issue Sink's sub-request to
/// [`LOG_WRITE`] runs under.
pub const CAP_LOG_WRITE: &str = "urn:cap:log:write";

/// The class of the issue Sink's log entry: one credential issued.
pub const ISSUANCE_CLASS: &str = "https://ikigai-rs.dev/ns/credential#Issuance";

/// The verifier's name.
pub const VERIFY: &str = "urn:credential:verify";

/// The pinned contexts every emitted document starts with, in order.
pub const CONTEXTS: [&str; 2] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
];

/// The media type of a secured credential (VC 2.0, section 6.1).
pub const MEDIA_VC: &str = "application/vc";

const ISSUER: &str = "urn:credential:issuer:name:{i}";
const ACHIEVEMENT: &str = "urn:credential:achievement:course:{c}:release:{r}";
const CREDENTIAL: &str = "urn:credential:id:{id}";
const ISSUE: &str = "urn:credential:issue:enrollment:{n}";
const MEDIA_JSON_LD: &str = "application/ld+json";
const MEDIA_PLAIN: &str = "text/plain";
const MEDIA_URI_LIST: &str = "text/uri-list";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_DATE_TIME_STAMP: &str = "http://www.w3.org/2001/XMLSchema#dateTimeStamp";
const XSD_ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
const LONGEST_NAME: usize = 200;
const LONGEST_EMAIL: usize = 254;

/// What the host configures: its issuers, and where the descriptions this module composes from
/// live. Configuration, not code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The issuers this host issues as, each named by its `{i}`.
    pub issuers: Vec<IssuerConfig>,
    /// An IRI template with `{course}` and `{release}`: the resource that describes a course
    /// release, read through the kernel to compose the achievement. It answers a JSON object:
    /// `name`, `description` and `criteria` as text, and optionally `alignment` (a list of
    /// objects with `targetName`, `targetUrl` and optionally `targetType`, `targetFramework`,
    /// `targetCode`, `targetDescription`) and `image` (`id`, an https IRI, and `caption`).
    pub release: String,
    /// An IRI template with `{enrollment}`: the resource that says whether an enrollment's
    /// completion rule holds, read through the kernel by the issue Sink. It answers a JSON
    /// object: `complete` (a boolean), `issuer`, `course`, `release`, and `student`, the opaque
    /// student id the issuer's credential IRI template takes.
    pub completion: String,
}

/// One issuer: its Open Badges `Profile`, its persistent-IRI template and its key history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerConfig {
    /// The `{i}` in `urn:credential:issuer:name:{i}`.
    pub name: String,
    /// The name people read, for example `iriref.org`.
    pub display_name: String,
    /// The issuer's web page.
    pub url: String,
    /// The issuer's `did:web` identifier, for example `did:web:iriref.org`.
    pub did: String,
    /// The template a credential's public `id` comes from, with `{student}` and `{cert}`, for
    /// example `https://iriref.org/learn/student/id/{student}/certificate/id/{cert}`.
    pub credential_iri: String,
    /// The key history, oldest first. A retired key stays, with `expires` set.
    pub keys: Vec<IssuerKey>,
}

/// One of an issuer's keys, as its `did:web` document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerKey {
    /// The fragment of the verification method: `key-1` names `did:web:iriref.org#key-1`.
    pub fragment: String,
    /// The public key, an Ed25519 Multikey (`z6Mk…`).
    pub public_key_multibase: String,
    /// The IRI of the private key in ikigai-secret, which `urn:sign:sign` reads through the
    /// kernel. This module never reads it.
    pub secret: String,
    /// The capability scopes reading [`secret`](Self::secret) needs, besides `urn:cap:sign`.
    pub secret_scopes: Vec<String>,
    /// When the key was retired, an `xsd:dateTimeStamp`; a credential whose `validFrom` is at
    /// or after it does not verify with this key, and nothing new is signed with it.
    pub expires: Option<String>,
    /// Set only when the key was compromised: nothing verifies with it.
    pub revoked: bool,
}

/// Where issued credentials are kept: each written once, under its id, for its enrollment.
pub trait AtomStore: Send + Sync {
    /// The credential stored under `id`.
    fn get(&self, id: &str) -> Option<Vec<u8>>;
    /// The id of the credential issued for `enrollment`, if one was.
    fn issued_for(&self, enrollment: &str) -> Option<String>;
    /// Store `credential` under `id` for `enrollment`, or refuse if either is already taken.
    /// Never replaces anything.
    fn put_once(&self, enrollment: &str, id: &str, credential: Vec<u8>) -> Result<(), Taken>;
}

/// Why [`AtomStore::put_once`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// The enrollment already has a credential, under this id.
    Enrollment(String),
    /// The id is already used.
    Id,
}

/// The credentials by id, and the id issued for each enrollment.
type Atoms = (BTreeMap<String, Vec<u8>>, BTreeMap<String, String>);

/// An [`AtomStore`] in memory, for tests and for a host that keeps nothing across restarts.
#[derive(Debug, Default)]
pub struct MemoryAtoms {
    inner: RwLock<Atoms>,
}

impl AtomStore for MemoryAtoms {
    fn get(&self, id: &str) -> Option<Vec<u8>> {
        self.inner.read().expect("atom lock").0.get(id).cloned()
    }

    fn issued_for(&self, enrollment: &str) -> Option<String> {
        self.inner
            .read()
            .expect("atom lock")
            .1
            .get(enrollment)
            .cloned()
    }

    fn put_once(&self, enrollment: &str, id: &str, credential: Vec<u8>) -> Result<(), Taken> {
        let mut inner = self.inner.write().expect("atom lock");
        if let Some(existing) = inner.1.get(enrollment) {
            return Err(Taken::Enrollment(existing.clone()));
        }
        if inner.0.contains_key(id) {
            return Err(Taken::Id);
        }
        inner.0.insert(id.to_owned(), credential);
        inner.1.insert(enrollment.to_owned(), id.to_owned());
        Ok(())
    }
}

/// Why a [`Config`] was refused. One sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

struct Checked {
    config: Config,
    release: UriTemplate,
    completion: UriTemplate,
    credential_iri: BTreeMap<String, UriTemplate>,
    store: Arc<dyn AtomStore>,
}

/// Bind the five resources over `config`, keeping issued credentials in `store`.
///
/// The space is built from configuration, so it stays anonymous: the host names what it builds.
/// A host binds ikigai-sign's `space()` (and its keystore) beside it, so `urn:sign:sign`
/// resolves.
pub fn space(config: Config, store: Arc<dyn AtomStore>) -> Result<EndpointSpace, ConfigError> {
    let template = |what: &str, source: &str, vars: &[&str]| {
        let parsed = UriTemplate::parse(source).map_err(|e| {
            ConfigError(format!(
                "The {what} template {source:?} is not a URI template: {e}."
            ))
        })?;
        let names: Vec<&str> = parsed.variables().collect();
        if let Some(missing) = vars.iter().find(|v| !names.contains(v)) {
            return Err(ConfigError(format!(
                "The {what} template {source:?} has no {{{missing}}}; add it."
            )));
        }
        Ok(parsed)
    };
    let release = template("release", &config.release, &["course", "release"])?;
    let completion = template("completion", &config.completion, &["enrollment"])?;
    let mut credential_iri = BTreeMap::new();
    for issuer in &config.issuers {
        if !segment(&issuer.name) {
            return Err(ConfigError(format!(
                "The issuer name {:?} must be letters, digits, '-', '.', '_' or '~'.",
                issuer.name
            )));
        }
        if !issuer.did.starts_with("did:web:") {
            return Err(ConfigError(format!(
                "The issuer {:?} must have a did:web identifier, not {:?}.",
                issuer.name, issuer.did
            )));
        }
        for key in &issuer.keys {
            multikey_decode(&key.public_key_multibase).map_err(|e| {
                ConfigError(format!(
                    "The key {}#{} is not an Ed25519 Multikey: {e}",
                    issuer.did, key.fragment
                ))
            })?;
            if let Some(expires) = &key.expires {
                parse_stamp(expires).map_err(|e| {
                    ConfigError(e.sentence(
                        &format!("The key {}#{}'s expiry", issuer.did, key.fragment),
                        expires,
                    ))
                })?;
            }
        }
        let parsed = template("credential IRI", &issuer.credential_iri, &["cert"])?;
        if credential_iri.insert(issuer.name.clone(), parsed).is_some() {
            return Err(ConfigError(format!(
                "The issuer name {:?} is configured twice.",
                issuer.name
            )));
        }
    }
    let shared = Arc::new(Checked {
        config,
        release,
        completion,
        credential_iri,
        store,
    });
    let bind = |space: EndpointSpace, pattern: &str, endpoint: Arc<dyn Endpoint>| {
        space.bind(
            UriTemplate::parse(pattern).expect("a fixed template"),
            Forward(endpoint),
        )
    };
    let space = EndpointSpace::new();
    let space = bind(space, ISSUER, Arc::new(Issuer(shared.clone())));
    let space = bind(space, ACHIEVEMENT, Arc::new(Achievement(shared.clone())));
    let space = bind(space, CREDENTIAL, Arc::new(Credential(shared.clone())));
    let space = bind(space, ISSUE, Arc::new(Issue(shared.clone())));
    Ok(space.bind(ikigai_core::Exact::new(VERIFY), VerifyResource(shared)))
}

/// An `Arc`'d endpoint, bound by value.
struct Forward(Arc<dyn Endpoint>);

#[async_trait]
impl Endpoint for Forward {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        self.0.invoke(inv).await
    }
    fn name(&self) -> &str {
        self.0.name()
    }
    fn describe(&self) -> Description {
        self.0.describe()
    }
}

/// A name segment this module accepts in an IRI: unreserved characters only, so `{id}` can
/// never swallow a `:form:page` after it.
fn segment(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

fn bound<'a>(inv: &'a Invocation<'_>, var: &str, what: &str) -> CoreResult<&'a str> {
    let value = inv.bindings.get(var).unwrap_or_default();
    if segment(value) {
        Ok(value)
    } else {
        Err(CoreError::InvalidArgument {
            name: var.into(),
            detail: format!("The {what} {value:?} must be letters, digits, '-', '.', '_' or '~'."),
        })
    }
}

fn json_repr(media: &str, value: &Value) -> Representation {
    Representation::new(
        ReprType::new(media),
        serde_json::to_vec(value).expect("JSON serializes"),
    )
}

fn text_repr(media: &str, text: String) -> Representation {
    Representation::new(
        ReprType::new(media).with_param("charset", "utf-8"),
        text.into_bytes(),
    )
}

fn source(iri: &str) -> CoreResult<Request> {
    let parsed = Iri::parse(iri)
        .map_err(|e| CoreError::Endpoint(format!("The IRI {iri:?} is not valid: {e}.")))?;
    Ok(Request::new(Verb::Source, parsed))
}

/// Read `iri` through the kernel as a bounded JSON object.
async fn read_object(
    inv: &Invocation<'_>,
    iri: &str,
    what: &str,
) -> CoreResult<Map<String, Value>> {
    let repr = inv.issue(source(iri)?).await?;
    match parse_bounded(&repr.bytes) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(CoreError::Endpoint(format!(
            "The {what} at {iri} is not a JSON object."
        ))),
        Err(e) => Err(CoreError::Endpoint(format!("The {what} at {iri}: {e}"))),
    }
}

fn text_field<'a>(object: &'a Map<String, Value>, key: &str, what: &str) -> CoreResult<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| CoreError::Endpoint(format!("The {what} has no {key} text.")))
}

fn https(text: &str) -> bool {
    text.starts_with("https://") && Iri::parse(text).is_ok()
}

// ---- the issuer ------------------------------------------------------------------------------

struct Issuer(Arc<Checked>);

impl Checked {
    fn issuer(&self, name: &str) -> CoreResult<&IssuerConfig> {
        self.config
            .issuers
            .iter()
            .find(|issuer| issuer.name == name)
            .ok_or_else(|| CoreError::NotFound(format!("There is no issuer named {name:?}.")))
    }
}

/// The issuer's Open Badges `Profile`, without a context.
fn profile(issuer: &IssuerConfig) -> Value {
    json!({
        "id": issuer.did,
        "type": ["Profile"],
        "name": issuer.display_name,
        "url": issuer.url,
    })
}

fn with_context(mut node: Value) -> Value {
    if let Value::Object(object) = &mut node {
        let mut out = Map::new();
        out.insert("@context".into(), json!(CONTEXTS));
        out.append(object);
        return Value::Object(out);
    }
    node
}

#[async_trait]
impl Endpoint for Issuer {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        let name = bound(inv, "i", "issuer name")?;
        let issuer = self.0.issuer(name)?;
        Ok(json_repr(MEDIA_JSON_LD, &with_context(profile(issuer))).cacheable())
    }

    fn name(&self) -> &str {
        "issuer"
    }

    fn describe(&self) -> Description {
        Description::new("issuer")
            .title("Credential issuer")
            .summary(
                "An issuer's Open Badges 3.0 Profile as JSON-LD: its did:web identifier, name \
                 and URL. Public; its key is a resource in ikigai-secret and never appears here.",
            )
            .verb(Verb::Source)
            .input(
                ArgSpec::new("i")
                    .summary("the issuer's name")
                    .class(XSD_STRING)
                    .binding(),
            )
            .output(MEDIA_JSON_LD)
    }
}

// ---- the achievement -------------------------------------------------------------------------

struct Achievement(Arc<Checked>);

impl Checked {
    /// Compose the Open Badges `Achievement` for a course release from its description, read
    /// through the kernel. Only the fields named in [`Config::release`] are taken, as data.
    async fn achievement(
        &self,
        inv: &Invocation<'_>,
        course: &str,
        release: &str,
    ) -> CoreResult<Value> {
        let mut vars = Bindings::new();
        vars.insert("course", course);
        vars.insert("release", release);
        let iri = self
            .release
            .expand_encoded(&vars)
            .expect("the template's variables were checked");
        let what = "course release description";
        let described = read_object(inv, &iri, what).await?;
        let id = format!("urn:credential:achievement:course:{course}:release:{release}");
        let mut achievement = json!({
            "id": id,
            "type": ["Achievement"],
            "name": text_field(&described, "name", what)?,
            "description": text_field(&described, "description", what)?,
            "criteria": {
                "id": format!("{id}:criteria"),
                "narrative": text_field(&described, "criteria", what)?,
            },
        });
        if let Some(list) = described.get("alignment") {
            let Some(list) = list.as_array() else {
                return Err(CoreError::Endpoint(format!(
                    "The {what}'s alignment is not a list."
                )));
            };
            let mut alignment = Vec::new();
            for (k, entry) in list.iter().enumerate() {
                let Some(entry) = entry.as_object() else {
                    return Err(CoreError::Endpoint(format!(
                        "The {what}'s alignment {k} is not an object."
                    )));
                };
                let target_url = text_field(entry, "targetUrl", "alignment")?;
                if !https(target_url) {
                    return Err(CoreError::Endpoint(format!(
                        "The {what}'s alignment {k} targetUrl is not an https IRI."
                    )));
                }
                let mut node = Map::new();
                node.insert("id".into(), format!("{id}:alignment:{k}").into());
                node.insert("type".into(), json!(["Alignment"]));
                node.insert(
                    "targetName".into(),
                    text_field(entry, "targetName", "alignment")?.into(),
                );
                node.insert("targetUrl".into(), target_url.into());
                for key in [
                    "targetType",
                    "targetFramework",
                    "targetCode",
                    "targetDescription",
                ] {
                    if let Some(value) = entry.get(key).and_then(Value::as_str) {
                        node.insert(key.into(), value.into());
                    }
                }
                alignment.push(Value::Object(node));
            }
            achievement["alignment"] = Value::Array(alignment);
        }
        if let Some(image) = described.get("image") {
            let image = image.as_object().ok_or_else(|| {
                CoreError::Endpoint(format!("The {what}'s image is not an object."))
            })?;
            let image_id = text_field(image, "id", "image")?;
            if !https(image_id) {
                return Err(CoreError::Endpoint(format!(
                    "The {what}'s image id is not an https IRI."
                )));
            }
            let mut node = json!({ "id": image_id, "type": "Image" });
            if let Some(caption) = image.get("caption").and_then(Value::as_str) {
                node["caption"] = caption.into();
            }
            achievement["image"] = node;
        }
        Ok(achievement)
    }
}

#[async_trait]
impl Endpoint for Achievement {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        let course = bound(inv, "c", "course")?;
        let release = bound(inv, "r", "release")?;
        let achievement = self.0.achievement(inv, course, release).await?;
        // A pure function of the release's description, whose freshness the kernel folds in.
        Ok(json_repr(MEDIA_JSON_LD, &with_context(achievement)).cacheable())
    }

    fn name(&self) -> &str {
        "achievement"
    }

    fn describe(&self) -> Description {
        Description::new("achievement")
            .title("Credential achievement")
            .summary(
                "The Open Badges 3.0 Achievement for a course release, as JSON-LD: its name, \
                 description, criteria as text, alignment and image, composed from the \
                 release's description read through the kernel. Every node has an id.",
            )
            .verb(Verb::Source)
            .input(
                ArgSpec::new("c")
                    .summary("the course")
                    .class(XSD_STRING)
                    .binding(),
            )
            .input(
                ArgSpec::new("r")
                    .summary("the release")
                    .class(XSD_STRING)
                    .binding(),
            )
            .output(MEDIA_JSON_LD)
            .fails(FailureClass::Unknown)
    }
}

// ---- the credential atom ---------------------------------------------------------------------

struct Credential(Arc<Checked>);

#[async_trait]
impl Endpoint for Credential {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        deny_unless(inv, &[CAP_READ], "urn:credential:id")?;
        let id = bound(inv, "id", "credential id")?;
        let bytes = self.0.store.get(id).ok_or_else(|| {
            CoreError::NotFound(format!("There is no credential with id {id:?}."))
        })?;
        // An atom: written once and never changed, so it may be kept as long as anyone likes.
        Ok(Representation::new(ReprType::new(MEDIA_VC), bytes).cacheable())
    }

    fn name(&self) -> &str {
        "credential"
    }

    fn describe(&self) -> Description {
        Description::new("credential")
            .title("Issued credential")
            .summary(
                "An issued Open Badges 3.0 credential with its eddsa-rdfc-2022 proof: an atom, \
                 written once by the issue Sink and never changed. Requires \
                 urn:cap:credential:read.",
            )
            .verb(Verb::Source)
            .requires(CAP_READ)
            .input(
                ArgSpec::new("id")
                    .summary("the credential's id")
                    .class(XSD_STRING)
                    .binding(),
            )
            .output(MEDIA_VC)
    }
}

/// The second line behind the kernel's declared-capability floor, for a path where no kernel
/// gate ran.
fn deny_unless(inv: &Invocation<'_>, scopes: &[&str], what: &str) -> CoreResult<()> {
    match scopes.iter().find(|scope| !inv.capability.allows(scope)) {
        Some(scope) => Err(CoreError::Denied(
            format!("{what} requires the {scope} capability").into(),
        )),
        None => Ok(()),
    }
}

// ---- the issue Sink --------------------------------------------------------------------------

struct Issue(Arc<Checked>);

/// The current time as an `xsd:dateTimeStamp` in UTC, whole seconds.
fn stamp(millis: u64) -> String {
    let epoch = DateTime::from_str("1970-01-01T00:00:00Z").expect("the epoch parses");
    let seconds = i64::try_from(millis / 1000).unwrap_or(i64::MAX);
    epoch
        .checked_add_day_time_duration(DayTimeDuration::new(seconds))
        .map(|at| at.to_string())
        .unwrap_or_else(|| "9999-12-31T23:59:59Z".into())
}

fn random_hex(bytes: usize) -> CoreResult<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf)
        .map_err(|e| CoreError::Endpoint(format!("No randomness was available: {e}.")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn holder_text<'a>(
    inv: &'a Invocation<'_>,
    name: &str,
    longest: usize,
) -> CoreResult<Option<&'a str>> {
    let Some(value) = inv.optional_str(name)? else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.chars().count() > longest || value.chars().any(char::is_control) {
        return Err(CoreError::InvalidArgument {
            name: name.into(),
            detail: format!(
                "The {name} must be 1 to {longest} characters with no control characters."
            ),
        });
    }
    Ok(Some(value))
}

impl Issue {
    fn signing_key<'a>(
        &self,
        issuer: &'a IssuerConfig,
        now: &DateTime,
    ) -> CoreResult<&'a IssuerKey> {
        issuer
            .keys
            .iter()
            .rev()
            .find(|key| {
                !key.revoked
                    && key
                        .expires
                        .as_deref()
                        .and_then(|e| parse_stamp(e).ok())
                        .is_none_or(|expires| *now < expires)
            })
            .ok_or_else(|| {
                CoreError::Conflict(format!(
                    "The issuer {:?} has no key in force, so nothing can be signed; add a key to its key history.",
                    issuer.name
                ))
            })
    }

    /// The holder's subject: their chosen display name, and either their `did:key` or a
    /// salted, hashed email. Never an identifier this module mints that recurs across
    /// credentials: the salt and the fragment ids are per credential.
    fn subject(
        &self,
        inv: &Invocation<'_>,
        public_id: &str,
        achievement: Value,
    ) -> CoreResult<Value> {
        let name = holder_text(inv, "name", LONGEST_NAME)?
            .ok_or_else(|| CoreError::MissingArgument("name".into()))?;
        let did = holder_text(inv, "did", LONGEST_EMAIL)?;
        let email = holder_text(inv, "email", LONGEST_EMAIL)?;
        let mut identifier = vec![json!({
            "id": format!("{public_id}#name"),
            "type": "IdentityObject",
            "identityType": "name",
            "hashed": false,
            "identityHash": name,
        })];
        let id = match (did, email) {
            (Some(did), None) => {
                let method = did_key_resolve(did).map_err(|e| CoreError::InvalidArgument {
                    name: "did".into(),
                    detail: format!("The did must be an Ed25519 did:key the holder controls: {e}"),
                })?;
                method.controller
            }
            (None, Some(email)) => {
                if !email.contains('@') {
                    return Err(CoreError::InvalidArgument {
                        name: "email".into(),
                        detail: "The email must be an address with an @.".into(),
                    });
                }
                let salt = random_hex(16)?;
                let hash: String = Sha256::digest(format!("{email}{salt}").as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                identifier.push(json!({
                    "id": format!("{public_id}#email"),
                    "type": "IdentityObject",
                    "identityType": "emailAddress",
                    "hashed": true,
                    "identityHash": format!("sha256${hash}"),
                    "salt": salt,
                }));
                format!("{public_id}#subject")
            }
            (Some(_), Some(_)) => {
                return Err(CoreError::InvalidArgument {
                    name: "email".into(),
                    detail: "Give either did or email, not both.".into(),
                })
            }
            (None, None) => return Err(CoreError::MissingArgument("did".into())),
        };
        Ok(json!({
            "id": id,
            "type": ["AchievementSubject"],
            "identifier": identifier,
            "achievement": achievement,
        }))
    }
}

/// Read the one value of `predicate` in ikigai-sign's signature graph.
fn sig_field(graph: &[u8], predicate: &str) -> CoreResult<String> {
    let mut found = None;
    for quad in oxrdfio::RdfParser::from_format(oxrdfio::RdfFormat::Turtle).for_slice(graph) {
        let quad = quad.map_err(|e| {
            CoreError::Endpoint(format!("The signature from {SIGN} is not Turtle: {e}."))
        })?;
        if quad.predicate.as_str() == predicate {
            let oxrdf::Term::Literal(literal) = quad.object else {
                return Err(CoreError::Endpoint(format!(
                    "The signature from {SIGN} has a {predicate} that is not text."
                )));
            };
            if found.replace(literal.value().to_owned()).is_some() {
                return Err(CoreError::Endpoint(format!(
                    "The signature from {SIGN} has more than one {predicate}."
                )));
            }
        }
    }
    found.ok_or_else(|| {
        CoreError::Endpoint(format!("The signature from {SIGN} has no {predicate}."))
    })
}

/// Ask `urn:sign:sign` for the Ed25519 signature over `message` with `key`, and check that it
/// is the issuer's published key that signed.
async fn sign_through_kernel(
    inv: &Invocation<'_>,
    message: &[u8; 64],
    key: &IssuerKey,
    public: &VerifyingKey,
) -> CoreResult<[u8; 64]> {
    let request = source(SIGN)?
        .with_arg("in", ArgRef::Inline(message.to_vec()))
        .with_arg("key", ArgRef::Inline(key.secret.as_bytes().to_vec()));
    let mut scopes = vec![CAP_SIGN.to_owned()];
    scopes.extend(key.secret_scopes.iter().cloned());
    let graph = inv.issue_attenuated(request, scopes).await?.bytes;
    let b64 = base64::engine::general_purpose::STANDARD;
    if sig_field(&graph, ikigai_sign::SIG_ALGORITHM)? != "Ed25519" {
        return Err(CoreError::Endpoint(format!(
            "The key {} is not an Ed25519 key; eddsa-rdfc-2022 needs one.",
            key.secret
        )));
    }
    let signer = b64
        .decode(sig_field(&graph, ikigai_sign::SIG_SIGNER)?)
        .unwrap_or_default();
    if signer != public.as_bytes() {
        return Err(CoreError::Endpoint(format!(
            "The key {} does not match the issuer's published key {}; fix the key history.",
            key.secret, key.public_key_multibase
        )));
    }
    let value = b64
        .decode(sig_field(&graph, ikigai_sign::SIG_VALUE)?)
        .unwrap_or_default();
    let signature: [u8; 64] = value
        .try_into()
        .map_err(|_| CoreError::Endpoint(format!("The signature from {SIGN} is not 64 bytes.")))?;
    public
        .verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| CoreError::Endpoint(format!("The signature from {SIGN} does not verify.")))?;
    Ok(signature)
}

/// Write the one ikigai-log entry an issuance gets: about the credential's public IRI, with the
/// enrollment and the issuer. ikigai-log attributes it to the caller's principal itself; the
/// subject's email, its hash and its did:key never reach the log.
async fn log_issuance(
    inv: &Invocation<'_>,
    enrollment: &str,
    issuer: &str,
    credential: &str,
) -> CoreResult<()> {
    let fields = format!("enrollment={enrollment} issuer={issuer}");
    let log = Iri::parse(LOG_WRITE).expect("a fixed IRI");
    let request = Request::new(Verb::Sink, log)
        .with_arg("class", ArgRef::Inline(ISSUANCE_CLASS.as_bytes().to_vec()))
        .with_arg("subject", ArgRef::Inline(credential.as_bytes().to_vec()))
        .with_arg("fields", ArgRef::Inline(fields.into_bytes()));
    let mut scopes = vec![CAP_LOG_WRITE.to_owned()];
    if let Some(principal) = inv.capability.principal() {
        scopes.push(format!("{PRINCIPAL_SCOPE_PREFIX}{principal}"));
    }
    inv.issue_attenuated(request, scopes).await.map_err(|e| {
        CoreError::Endpoint(format!(
            "The credential {credential} was issued, but its {LOG_WRITE} entry failed: {e}."
        ))
    })?;
    Ok(())
}

#[async_trait]
impl Endpoint for Issue {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        deny_unless(
            inv,
            &[CAP_ISSUE, CAP_SIGN, CAP_LOG_WRITE],
            "urn:credential:issue",
        )?;
        let enrollment = bound(inv, "n", "enrollment")?;
        let shared = &self.0;
        if let Some(id) = shared.store.issued_for(enrollment) {
            return Err(CoreError::Conflict(format!(
                "Enrollment {enrollment} already has its credential, urn:credential:id:{id}; a credential is issued once."
            )));
        }
        let mut vars = Bindings::new();
        vars.insert("enrollment", enrollment);
        let completion_iri = shared
            .completion
            .expand_encoded(&vars)
            .expect("the template's variables were checked");
        let what = "enrollment's completion";
        let completion = read_object(inv, &completion_iri, what).await?;
        if completion.get("complete") != Some(&Value::Bool(true)) {
            return Err(CoreError::Conflict(format!(
                "Enrollment {enrollment} has not met its release's completion rule, so no credential is issued."
            )));
        }
        let field = |key: &str| -> CoreResult<&str> {
            let value = text_field(&completion, key, what)?;
            if segment(value) {
                Ok(value)
            } else {
                Err(CoreError::Endpoint(format!(
                    "The {what}'s {key} {value:?} must be letters, digits, '-', '.', '_' or '~'."
                )))
            }
        };
        let issuer = shared.issuer(field("issuer")?)?;
        let (course, release, student) = (field("course")?, field("release")?, field("student")?);
        let now = inv.now().ok_or_else(|| {
            CoreError::Endpoint("The kernel has no clock, so validFrom cannot be set.".into())
        })?;
        let now = stamp(now.as_millis());
        let at = parse_stamp(&now)
            .map_err(|_| CoreError::Endpoint("The clock is out of range.".into()))?;
        let key = self.signing_key(issuer, &at)?;
        let public = multikey_decode(&key.public_key_multibase).expect("checked at configuration");

        let achievement = source(&format!(
            "urn:credential:achievement:course:{course}:release:{release}"
        ))?;
        let achievement = inv.issue(achievement).await?;
        let Ok(Value::Object(mut achievement)) = parse_bounded(&achievement.bytes) else {
            return Err(CoreError::Endpoint(
                "The achievement is not a JSON object.".into(),
            ));
        };
        achievement.remove("@context");

        let id = random_hex(16)?;
        let mut vars = Bindings::new();
        vars.insert("student", student);
        vars.insert("cert", id.as_str());
        let public_id = shared.credential_iri[&issuer.name]
            .expand_encoded(&vars)
            .ok_or_else(|| {
                CoreError::Endpoint(format!(
                    "The issuer {:?}'s credential IRI template takes only {{student}} and {{cert}}.",
                    issuer.name
                ))
            })?;
        let name = text_field(&achievement, "name", "achievement")?.to_owned();
        let mut credential = json!({
            "@context": CONTEXTS,
            "id": public_id,
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "name": name,
            "issuer": profile(issuer),
            "validFrom": now,
            "credentialSubject": self.subject(inv, &public_id, Value::Object(achievement))?,
        });
        if let Some(evidence) = inv.optional_str("evidence")? {
            if !https(evidence) {
                return Err(CoreError::InvalidArgument {
                    name: "evidence".into(),
                    detail: "The evidence must be an https IRI the holder chose to make public."
                        .into(),
                });
            }
            credential["evidence"] = json!([{ "id": evidence, "type": ["Evidence"] }]);
        }
        let options = ProofOptions {
            created: now,
            verification_method: format!("{}#{}", issuer.did, key.fragment),
            proof_purpose: "assertionMethod".into(),
        };
        let prepared =
            prepare(&credential, &options).map_err(|e| CoreError::Endpoint(e.to_string()))?;
        let signature = sign_through_kernel(inv, &prepared.message, key, &public).await?;
        let secured = prepared.secure(&signature);
        let bytes = serde_json::to_vec(&secured).expect("JSON serializes");
        match shared.store.put_once(enrollment, &id, bytes) {
            Ok(()) => {}
            Err(Taken::Enrollment(existing)) => {
                return Err(CoreError::Conflict(format!(
                    "Enrollment {enrollment} already has its credential, urn:credential:id:{existing}; a credential is issued once."
                )))
            }
            Err(Taken::Id) => {
                return Err(CoreError::Endpoint("A fresh credential id was already taken; issue again.".into()))
            }
        }
        log_issuance(inv, enrollment, &issuer.name, &public_id).await?;
        Ok(text_repr(
            MEDIA_URI_LIST,
            format!("urn:credential:id:{id}\r\n"),
        ))
    }

    fn name(&self) -> &str {
        "issue"
    }

    fn describe(&self) -> Description {
        let mut description = Description::new("issue")
            .title("Issue a credential")
            .summary(
                "Issue the Open Badges 3.0 credential for an enrollment, signed with \
                 eddsa-rdfc-2022 through urn:sign:sign. Sealed: Conflict unless the \
                 enrollment's completion rule holds, and Conflict once it has its credential. \
                 The holder gives their display name and either a did:key they control or an \
                 email, which is salted and hashed; evidence is only what they choose to make \
                 public. Answers the new credential atom's name.",
            )
            .verb(Verb::Sink)
            .requires(CAP_ISSUE)
            .requires(CAP_SIGN)
            .requires(CAP_LOG_WRITE)
            .input(
                ArgSpec::new("n")
                    .summary("the enrollment")
                    .class(XSD_STRING)
                    .binding(),
            )
            .input(
                ArgSpec::new("name")
                    .summary("the holder's chosen display name")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("did")
                    .summary("an Ed25519 did:key the holder controls")
                    .class(XSD_ANY_URI)
                    .optional(),
            )
            .input(
                ArgSpec::new("email")
                    .summary("the holder's email, emitted only salted and hashed")
                    .class(XSD_STRING)
                    .optional(),
            )
            .input(
                ArgSpec::new("evidence")
                    .summary("an https IRI of evidence the holder chose to make public")
                    .class(XSD_ANY_URI)
                    .optional(),
            )
            .group(InputGroup::exactly_one(["did", "email"]))
            .output(MEDIA_URI_LIST)
            .fails(FailureClass::Unknown);
        let mut extra: Vec<&str> = Vec::new();
        for issuer in &self.0.config.issuers {
            for key in &issuer.keys {
                for scope in &key.secret_scopes {
                    if !extra.contains(&scope.as_str()) {
                        extra.push(scope);
                    }
                }
            }
        }
        for scope in extra {
            description = description.requires(scope);
        }
        description
    }
}

// ---- the verifier ----------------------------------------------------------------------------

struct VerifyResource(Arc<Checked>);

/// The DID a verification method belongs to: the part before `#`.
fn did_of(method: &str) -> &str {
    method.split_once('#').map_or(method, |(did, _)| did)
}

impl Checked {
    /// The issuer key `method` named as of `valid_from`, from the key history; a `did:key` is
    /// its own key. Nothing is fetched.
    fn key_as_of(&self, method: &str, valid_from: Option<&str>) -> Result<VerifyingKey, String> {
        if method.starts_with(DID_KEY_PREFIX) {
            let resolved = did_key_resolve(method)
                .map_err(|e| format!("its did:key {method} is not usable: {e}"))?;
            if resolved.id != method {
                return Err(format!(
                    "its verification method {method} is not the did:key's own key."
                ));
            }
            return Ok(resolved.key);
        }
        let did = did_of(method);
        let fragment = method.split_once('#').map(|(_, f)| f);
        let key = self
            .config
            .issuers
            .iter()
            .filter(|issuer| issuer.did == did)
            .flat_map(|issuer| issuer.keys.iter())
            .find(|key| Some(key.fragment.as_str()) == fragment)
            .ok_or_else(|| {
                format!("its issuer's key {method} is not in this verifier's key history, and keys are never fetched.")
            })?;
        if key.revoked {
            return Err(format!("its issuer's key {method} was revoked."));
        }
        if let Some(expires) = &key.expires {
            let Some(from) = valid_from else {
                return Err(format!(
                    "it has no validFrom, so it cannot be shown to predate the expiry of its issuer's key {method}."
                ));
            };
            let (Ok(from), Ok(until)) = (parse_stamp(from), parse_stamp(expires)) else {
                return Err("its validFrom could not be compared with its key's expiry.".into());
            };
            if from >= until {
                return Err(format!(
                    "its issuer's key {method} had expired at {expires}, before its validFrom."
                ));
            }
        }
        multikey_decode(&key.public_key_multibase).map_err(|e| e.to_string())
    }
}

/// The issuer's id: `issuer` is an IRI or an object with an `id`.
fn issuer_id(document: &Value) -> Option<&str> {
    match document.get("issuer")? {
        Value::String(id) => Some(id),
        Value::Object(profile) => profile.get("id")?.as_str(),
        _ => None,
    }
}

#[async_trait]
impl Endpoint for VerifyResource {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        let bytes = match inv.inline_arg("in") {
            Err(CoreError::MissingArgument(_)) => inv
                .inline_arg("content")
                .map_err(|_| CoreError::MissingArgument("in".into()))?,
            other => other?,
        };
        let given_now = inv.optional_str("now")?;
        let now = match given_now {
            Some(now) => now.to_owned(),
            None => inv
                .now()
                .map(|t| stamp(t.as_millis()))
                .ok_or_else(|| CoreError::MissingArgument("now".into()))?,
        };
        let invalid_input = |e: crate::Error| CoreError::InvalidArgument {
            name: if given_now.is_some()
                && matches!(&e, crate::Error::Input(s) if s.starts_with("The verifier's clock"))
            {
                "now".into()
            } else {
                "in".into()
            },
            detail: e.to_string(),
        };
        let document = parse_bounded(bytes).map_err(invalid_input)?;
        let method = document
            .get("proof")
            .and_then(|p| p.get("verificationMethod"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let verdict = match issuer_id(&document) {
            None => Verdict::Invalid("it names no issuer.".into()),
            Some(issuer) if !method.is_empty() && did_of(method) != issuer => {
                Verdict::Invalid(format!(
                    "its proof's key {method} belongs to {}, not to its issuer {issuer}.",
                    did_of(method)
                ))
            }
            Some(_) => crate::verify(bytes, &now, |m, from| self.0.key_as_of(m, from))
                .map_err(invalid_input)?,
        };
        let sentence = format!(
            "{} Its status was not checked: status lists are not built yet.",
            verdict.sentence()
        );
        let repr = text_repr(MEDIA_PLAIN, sentence);
        // A pure function of the credential, the clock given and the key history; with the
        // kernel's clock it is not.
        Ok(if given_now.is_some() {
            repr.cacheable()
        } else {
            repr
        })
    }

    fn name(&self) -> &str {
        "verify"
    }

    fn describe(&self) -> Description {
        Description::new("verify")
            .title("Verify a credential")
            .summary(
                "Verify an Open Badges 3.0 credential's eddsa-rdfc-2022 proof: a credential \
                 in, a verdict sentence out. Checks the proof, that the proof's key belongs to \
                 the issuer, the issuer's key as of validFrom from the key history, and the \
                 validity window. Nothing is fetched and nothing records who checked what. \
                 Open: no capability required.",
            )
            .verb(Verb::Source)
            .input(
                ArgSpec::new("in")
                    .summary("the credential, JSON-LD (or piped as `content`)")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("content")
                    .summary("the credential, the piped alternative to `in`")
                    .class(XSD_STRING)
                    .optional(),
            )
            .input(
                ArgSpec::new("now")
                    .summary("the verifier's clock as an xsd:dateTimeStamp; the kernel's clock if left out")
                    .class(XSD_DATE_TIME_STAMP)
                    .optional(),
            )
            .output(MEDIA_PLAIN)
            .fails(FailureClass::Unknown)
    }
}
