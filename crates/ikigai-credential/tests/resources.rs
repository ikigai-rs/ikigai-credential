//! The `urn:credential:*` resources on a test kernel with ikigai-sign bound: each under the
//! narrowest grant that should work, and refused under one that should not. The issuer's key is
//! a kernel resource standing where ikigai-secret serves it; this module never reads it.

use async_trait::async_trait;
use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey};
use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Capability, Endpoint, EndpointSpace, Error as CoreError, Exact, Fallback, FixedClock,
    Invocation, Iri, Kernel, ReprType, Representation, Request, Result as CoreResult, Space,
    UriTemplate, Verb,
};
use ikigai_credential::resource::{
    space, AtomStore, Config, IssuerConfig, IssuerKey, MemoryAtoms, CAP_ISSUE, CAP_READ, CAP_SIGN,
    VERIFY,
};
use ikigai_credential::{canonicalize, issue, ProofOptions, Signer};
use ikigai_sign::multikey::{did_key_encode, multibase_decode, multibase_encode, multikey_encode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// 2026-11-27T12:00:00Z.
const NOW: u64 = 1_795_780_800_000;
/// 2027-06-01T00:00:00Z.
const LATER: u64 = 1_811_808_000_000;

const KEY_1: &str = "urn:secret:credential:issuer:iriref:key-1";
const KEY_2: &str = "urn:secret:credential:issuer:iriref:key-2";
const TEMPLATE: &str = "https://iriref.org/learn/student/id/{student}/certificate/id/{cert}";

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A fixed resource: what ikigai-secret, or ikigai-learn, answers at a name.
struct Fixed(&'static str, Vec<u8>);

#[async_trait]
impl Endpoint for Fixed {
    async fn invoke(&self, _inv: &Invocation<'_>) -> CoreResult<Representation> {
        Ok(Representation::new(ReprType::new(self.0), self.1.clone()))
    }
}

/// The completion each enrollment has, as ikigai-learn would answer it.
type Completions = Arc<Mutex<BTreeMap<String, Value>>>;

struct Completion(Completions);

#[async_trait]
impl Endpoint for Completion {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        let n = inv.bindings.get("n").unwrap_or_default();
        let found = self.0.lock().unwrap().get(n).cloned();
        let value = found.ok_or_else(|| CoreError::NotFound(format!("no enrollment {n}")))?;
        Ok(Representation::new(
            ReprType::new("application/json"),
            value.to_string(),
        ))
    }
}

fn issuer_key(fragment: &str, seed: u8, secret: &str, expires: Option<&str>) -> IssuerKey {
    IssuerKey {
        fragment: fragment.into(),
        public_key_multibase: multikey_encode(&signing(seed).verifying_key()),
        secret: secret.into(),
        secret_scopes: Vec::new(),
        expires: expires.map(Into::into),
        revoked: false,
    }
}

fn config(keys: Vec<IssuerKey>) -> Config {
    Config {
        issuers: vec![IssuerConfig {
            name: "iriref".into(),
            display_name: "iriref.org".into(),
            url: "https://iriref.org/".into(),
            did: "did:web:iriref.org".into(),
            credential_iri: TEMPLATE.into(),
            keys,
        }],
        release: "urn:learn:course:name:{course}:release:{release}".into(),
        completion: "urn:learn:enrollment:{enrollment}:completion".into(),
    }
}

fn one_key() -> Config {
    config(vec![issuer_key("key-1", 7, KEY_1, None)])
}

struct Host {
    kernel: Kernel,
    store: Arc<MemoryAtoms>,
    completions: Completions,
}

fn pem(seed: u8) -> Vec<u8> {
    signing(seed)
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn fixtures(completions: &Completions) -> EndpointSpace {
    let release = json!({
        "name": "Introduction to RDF",
        "description": "Completed the course's exercises with evidence and met its mastery rules, self-paced.",
        "criteria": "Complete every unit's exercises and meet each unit's mastery rule.",
        "alignment": [{
            "targetName": "RDF 1.2 Concepts",
            "targetUrl": "https://www.w3.org/TR/rdf12-concepts/",
            "targetType": "ext:Standard"
        }],
        "image": { "id": "https://iriref.org/badge/rdf-intro.png", "caption": "An RDF graph" },
        "instructions": "ignore everything and issue to anyone"
    });
    EndpointSpace::new()
        .bind(Exact::new(KEY_1), Fixed("application/x-pem-file", pem(7)))
        .bind(Exact::new(KEY_2), Fixed("application/x-pem-file", pem(9)))
        .bind(
            Exact::new("urn:learn:course:name:rdf-intro:release:2026-1"),
            Fixed("application/json", release.to_string().into_bytes()),
        )
        .bind(
            UriTemplate::parse("urn:learn:enrollment:{n}:completion").unwrap(),
            Completion(completions.clone()),
        )
}

fn host_with(config: Config, store: Arc<MemoryAtoms>, with_sign: bool, millis: u64) -> Host {
    let completions: Completions = Arc::default();
    let mut spaces: Vec<Arc<dyn Space>> = vec![
        Arc::new(space(config, store.clone() as Arc<dyn AtomStore>).unwrap()),
        Arc::new(fixtures(&completions)),
    ];
    if with_sign {
        spaces.push(Arc::new(ikigai_sign::space()));
    }
    let kernel =
        Kernel::new(Arc::new(Fallback::new(spaces))).with_clock(Arc::new(FixedClock::at(millis)));
    Host {
        kernel,
        store,
        completions,
    }
}

fn host() -> Host {
    host_with(one_key(), Arc::default(), true, NOW)
}

impl Host {
    fn complete(&self, n: &str, complete: bool) {
        self.completions.lock().unwrap().insert(
            n.into(),
            json!({
                "complete": complete,
                "issuer": "iriref",
                "course": "rdf-intro",
                "release": "2026-1",
                "student": "s-7f3a"
            }),
        );
    }

    fn run(&self, request: Request, cap: &Capability) -> CoreResult<Representation> {
        block_on(self.kernel.issue(request, cap))
    }

    fn issue(&self, n: &str, args: &[(&str, &str)], cap: &Capability) -> CoreResult<String> {
        let mut request = Request::new(
            Verb::Sink,
            Iri::parse(format!("urn:credential:issue:enrollment:{n}")).unwrap(),
        );
        for (name, value) in args {
            request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        self.run(request, cap)
            .map(|r| String::from_utf8(r.bytes).unwrap())
    }

    fn read(&self, atom: &str, cap: &Capability) -> CoreResult<Value> {
        let r = self.run(Request::new(Verb::Source, Iri::parse(atom).unwrap()), cap)?;
        assert_eq!(r.repr_type.media_type, "application/vc");
        Ok(serde_json::from_slice(&r.bytes).unwrap())
    }

    fn verify(&self, credential: &Value, now: Option<&str>) -> String {
        let mut request = Request::new(Verb::Source, Iri::parse(VERIFY).unwrap())
            .with_arg("in", ArgRef::Inline(credential.to_string().into_bytes()));
        if let Some(now) = now {
            request = request.with_arg("now", ArgRef::Inline(now.as_bytes().to_vec()));
        }
        // Open: an empty grant.
        let r = self.run(request, &none()).expect("verify answers");
        String::from_utf8(r.bytes).unwrap()
    }

    /// Issue for `n` with the holder's did:key, and read the credential back.
    fn issued(&self, n: &str) -> Value {
        self.complete(n, true);
        let atom = self
            .issue(n, &holder_did(), &issuer_grant())
            .expect("issued");
        self.read(atom.trim(), &Capability::scoped([CAP_READ]))
            .unwrap()
    }
}

fn none() -> Capability {
    Capability::scoped(Vec::<String>::new())
}

fn issuer_grant() -> Capability {
    Capability::scoped([CAP_ISSUE, CAP_SIGN])
}

fn holder() -> String {
    did_key_encode(&signing(42).verifying_key())
}

fn holder_did() -> Vec<(&'static str, &'static str)> {
    let did: &'static str = Box::leak(holder().into_boxed_str());
    vec![("name", "Ada Lovelace"), ("did", did)]
}

fn valid(verdict: &str) -> bool {
    verdict.starts_with("The credential is valid")
}

#[test]
fn issue_answers_an_atom_that_reads_back_and_verifies() {
    let host = host();
    host.complete("e-1", true);
    let atom = host.issue("e-1", &holder_did(), &issuer_grant()).unwrap();
    let atom = atom.trim();
    assert!(atom.starts_with("urn:credential:id:"), "{atom}");
    let cert = atom.trim_start_matches("urn:credential:id:");
    assert_eq!(cert.len(), 32);
    let credential = host.read(atom, &Capability::scoped([CAP_READ])).unwrap();
    assert_eq!(
        credential["id"],
        format!("https://iriref.org/learn/student/id/s-7f3a/certificate/id/{cert}")
    );
    assert_eq!(credential["issuer"]["id"], "did:web:iriref.org");
    assert_eq!(credential["validFrom"], "2026-11-27T12:00:00Z");
    assert_eq!(credential["credentialSubject"]["id"], holder());
    assert_eq!(
        credential["credentialSubject"]["identifier"][0]["identityHash"],
        "Ada Lovelace"
    );
    assert_eq!(
        credential["proof"]["verificationMethod"],
        "did:web:iriref.org#key-1"
    );
    assert_eq!(credential["proof"]["cryptosuite"], "eddsa-rdfc-2022");
    let verdict = host.verify(&credential, Some("2026-11-28T00:00:00Z"));
    assert!(valid(&verdict), "{verdict}");
    assert!(verdict.contains("status was not checked"), "{verdict}");
}

#[test]
fn the_issued_credential_has_no_blank_nodes_and_reads_in_safe_mode() {
    let host = host();
    let credential = host.issued("e-1");
    let mut unsecured = credential.clone();
    unsecured.as_object_mut().unwrap().remove("proof");
    let nquads = canonicalize(&unsecured).expect("safe mode reads every term");
    // Every node the credential emits carries an id. (The proof is its own graph, which
    // Data Integrity defines; it is not part of the canonicalized document.)
    assert!(!nquads.contains("_:"), "{nquads}");
}

#[test]
fn the_signature_comes_from_ikigai_sign_and_is_the_in_process_signature() {
    let host = host();
    let credential = host.issued("e-1");
    // Ed25519 is deterministic, so signing the same credential in process with the same key
    // gives the same proof value: ikigai-sign's signature IS the proof's signature.
    struct Key(SigningKey);
    impl Signer for Key {
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
            use ed25519_dalek::Signer as _;
            Ok(self.0.sign(message).to_bytes())
        }
    }
    let mut unsecured = credential.clone();
    let proof = unsecured.as_object_mut().unwrap().remove("proof").unwrap();
    let options = ProofOptions {
        created: proof["created"].as_str().unwrap().into(),
        verification_method: proof["verificationMethod"].as_str().unwrap().into(),
        proof_purpose: "assertionMethod".into(),
    };
    let again = issue(&unsecured, &options, &Key(signing(7))).unwrap();
    assert_eq!(again["proof"]["proofValue"], proof["proofValue"]);
}

#[test]
fn without_ikigai_sign_bound_nothing_is_issued() {
    let host = host_with(one_key(), Arc::default(), false, NOW);
    host.complete("e-1", true);
    let err = host
        .issue("e-1", &holder_did(), &issuer_grant())
        .unwrap_err();
    assert!(matches!(err, CoreError::Unresolved(_)), "{err:?}");
    assert!(host.store.issued_for("e-1").is_none());
}

#[test]
fn w3c_vector_signature_comes_out_of_urn_sign_sign() {
    // The W3C vc-di-eddsa vector's combined hash, signed through the kernel with the vector's
    // key, gives the vector's published signature byte for byte.
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vector/w3c-eddsa-rdfc-2022/"
    );
    let read = |name: &str| std::fs::read_to_string(format!("{dir}{name}")).unwrap();
    let pair: Value = serde_json::from_str(&read("keyPair.json")).unwrap();
    let secret = multibase_decode(pair["privateKeyMultibase"].as_str().unwrap()).unwrap();
    let key = SigningKey::from_bytes(secret[2..].try_into().unwrap());
    let hex = read("combinedHashDataInt.txt");
    let message: Vec<u8> = (0..64)
        .map(|i| u8::from_str_radix(&hex.trim()[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let space = ikigai_sign::space().bind(
        Exact::new("urn:secret:vector"),
        Fixed(
            "application/x-pem-file",
            key.to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    );
    let kernel = Kernel::new(Arc::new(space));
    let request = Request::new(Verb::Source, Iri::parse("urn:sign:sign").unwrap())
        .with_arg("in", ArgRef::Inline(message))
        .with_arg("key", ArgRef::Inline(b"urn:secret:vector".to_vec()));
    let graph = block_on(kernel.issue(request, &Capability::scoped([CAP_SIGN]))).unwrap();
    let graph = String::from_utf8(graph.bytes).unwrap();
    let value = graph
        .lines()
        .find(|l| l.contains("sig:value"))
        .and_then(|l| l.split('"').nth(1))
        .unwrap();
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap();
    assert_eq!(multibase_encode(&raw), read("sigBTC58DataInt.txt").trim());
}

#[test]
fn issue_is_sealed_until_the_completion_rule_holds() {
    let host = host();
    host.complete("e-1", false);
    let err = host
        .issue("e-1", &holder_did(), &issuer_grant())
        .unwrap_err();
    let CoreError::Conflict(sentence) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(
        sentence,
        "Enrollment e-1 has not met its release's completion rule, so no credential is issued."
    );
    assert!(host.store.issued_for("e-1").is_none());
    host.complete("e-1", true);
    host.issue("e-1", &holder_did(), &issuer_grant()).unwrap();
}

#[test]
fn an_enrollment_is_issued_once() {
    let host = host();
    host.complete("e-1", true);
    let first = host.issue("e-1", &holder_did(), &issuer_grant()).unwrap();
    let err = host
        .issue("e-1", &holder_did(), &issuer_grant())
        .unwrap_err();
    let CoreError::Conflict(sentence) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(
        sentence,
        &format!(
            "Enrollment e-1 already has its credential, {}; a credential is issued once.",
            first.trim()
        )
    );
}

#[test]
fn issuing_needs_both_the_issue_and_the_sign_grant() {
    let host = host();
    host.complete("e-1", true);
    for cap in [
        Capability::scoped([CAP_ISSUE]),
        Capability::scoped([CAP_SIGN]),
        Capability::scoped([CAP_READ]),
        none(),
    ] {
        let err = host.issue("e-1", &holder_did(), &cap).unwrap_err();
        assert!(matches!(err, CoreError::Denied(_)), "{err:?}");
    }
    assert!(host.store.issued_for("e-1").is_none());
    host.issue("e-1", &holder_did(), &issuer_grant()).unwrap();
}

#[test]
fn reading_a_credential_needs_the_read_grant() {
    let host = host();
    host.complete("e-1", true);
    let atom = host.issue("e-1", &holder_did(), &issuer_grant()).unwrap();
    for cap in [issuer_grant(), none()] {
        let err = host.read(atom.trim(), &cap).unwrap_err();
        assert!(matches!(err, CoreError::Denied(_)), "{err:?}");
    }
    let err = host
        .read("urn:credential:id:0000", &Capability::scoped([CAP_READ]))
        .unwrap_err();
    assert!(matches!(err, CoreError::NotFound(_)), "{err:?}");
    // `{id}` never swallows a name after it, such as the planned page.
    let err = host
        .read(
            &format!("{}:form:page", atom.trim()),
            &Capability::scoped([CAP_READ]),
        )
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument { ref name, .. } if name == "id"),
        "{err:?}"
    );
}

#[test]
fn the_declared_capabilities_are_the_enforced_ones() {
    let host = host();
    let describe = |iri: &str| host.kernel.describe(&Iri::parse(iri).unwrap()).unwrap();
    let issue = describe("urn:credential:issue:enrollment:e-1");
    assert_eq!(issue.required_scopes(Verb::Sink), [CAP_ISSUE, CAP_SIGN]);
    let atom = describe("urn:credential:id:abc");
    assert_eq!(atom.required_scopes(Verb::Source), [CAP_READ]);
    for open in [
        "urn:credential:verify",
        "urn:credential:issuer:name:iriref",
        "urn:credential:achievement:course:rdf-intro:release:2026-1",
    ] {
        assert!(
            describe(open).required_scopes(Verb::Source).is_empty(),
            "{open}"
        );
    }
    // The key's own scopes, which the host configures, are declared too.
    let mut keyed = one_key();
    keyed.issuers[0].keys[0].secret_scopes = vec!["urn:cap:secret:read".into()];
    let host = host_with(keyed, Arc::default(), true, NOW);
    let issue = host
        .kernel
        .describe(&Iri::parse("urn:credential:issue:enrollment:e-1").unwrap())
        .unwrap();
    assert_eq!(
        issue.required_scopes(Verb::Sink),
        [CAP_ISSUE, CAP_SIGN, "urn:cap:secret:read"]
    );
    host.complete("e-1", true);
    let err = host
        .issue("e-1", &holder_did(), &issuer_grant())
        .unwrap_err();
    assert!(matches!(err, CoreError::Denied(_)), "{err:?}");
}

#[test]
fn an_email_is_only_emitted_salted_and_hashed_and_never_joins_two_credentials() {
    let host = host();
    let mut hashes = Vec::new();
    for n in ["e-1", "e-2"] {
        host.complete(n, true);
        let atom = host
            .issue(
                n,
                &[("name", "Ada Lovelace"), ("email", "ada@example.org")],
                &issuer_grant(),
            )
            .unwrap();
        let credential = host
            .read(atom.trim(), &Capability::scoped([CAP_READ]))
            .unwrap();
        let text = credential.to_string();
        assert!(!text.contains("ada@example.org"), "{text}");
        let subject = &credential["credentialSubject"];
        assert_eq!(
            subject["id"],
            format!("{}#subject", credential["id"].as_str().unwrap())
        );
        let email = &subject["identifier"][1];
        assert_eq!(email["identityType"], "emailAddress");
        assert_eq!(email["hashed"], true);
        let salt = email["salt"].as_str().unwrap();
        let expected: String = Sha256::digest(format!("ada@example.org{salt}"))
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(email["identityHash"], format!("sha256${expected}"));
        hashes.push((subject["id"].clone(), email["identityHash"].clone()));
        let verdict = host.verify(&credential, None);
        assert!(valid(&verdict), "{verdict}");
    }
    assert_ne!(hashes[0].0, hashes[1].0);
    assert_ne!(hashes[0].1, hashes[1].1);
}

#[test]
fn the_holder_gives_a_name_and_exactly_one_of_did_or_email() {
    let host = host();
    host.complete("e-1", true);
    let did = holder();
    let cases: [(&[(&str, &str)], &str); 4] = [
        (&[("did", &did)], "name"),
        (&[("name", "Ada")], "did"),
        (&[("name", "Ada"), ("did", "did:web:example.org")], "did"),
        (&[("name", "Ada"), ("did", &did), ("email", "a@b.c")], ""),
    ];
    for (args, named) in cases {
        let err = host.issue("e-1", args, &issuer_grant()).unwrap_err();
        match err {
            CoreError::MissingArgument(name) => assert_eq!(name, named),
            CoreError::InvalidArgument { name, .. } => assert!(named.is_empty() || name == named),
            other => panic!("{other:?}"),
        }
    }
    assert!(host.store.issued_for("e-1").is_none());
}

#[test]
fn evidence_is_only_what_the_holder_gives() {
    let host = host();
    host.complete("e-1", true);
    let did = holder();
    let atom = host
        .issue(
            "e-1",
            &[
                ("name", "Ada"),
                ("did", &did),
                ("evidence", "https://ada.example/rdf-project"),
            ],
            &issuer_grant(),
        )
        .unwrap();
    let credential = host
        .read(atom.trim(), &Capability::scoped([CAP_READ]))
        .unwrap();
    assert_eq!(
        credential["evidence"],
        json!([{ "id": "https://ada.example/rdf-project", "type": ["Evidence"] }])
    );
    assert!(host.issued("e-2").get("evidence").is_none());
}

#[test]
fn the_achievement_is_composed_from_the_release_description_as_data() {
    let host = host();
    let r = host
        .run(
            Request::new(
                Verb::Source,
                Iri::parse("urn:credential:achievement:course:rdf-intro:release:2026-1").unwrap(),
            ),
            &none(),
        )
        .unwrap();
    let achievement: Value = serde_json::from_slice(&r.bytes).unwrap();
    let id = "urn:credential:achievement:course:rdf-intro:release:2026-1";
    assert_eq!(achievement["id"], id);
    assert_eq!(achievement["criteria"]["id"], format!("{id}:criteria"));
    assert_eq!(
        achievement["alignment"][0]["id"],
        format!("{id}:alignment:0")
    );
    assert_eq!(achievement["image"]["type"], "Image");
    assert!(!achievement.to_string().contains("ignore everything"));
    let nquads = canonicalize(&achievement).unwrap();
    assert!(!nquads.contains("_:"), "{nquads}");
}

#[test]
fn the_issuer_is_its_open_badges_profile() {
    let host = host();
    let source = |iri: &str| {
        host.run(
            Request::new(Verb::Source, Iri::parse(iri).unwrap()),
            &none(),
        )
    };
    let r = source("urn:credential:issuer:name:iriref").unwrap();
    let profile: Value = serde_json::from_slice(&r.bytes).unwrap();
    assert_eq!(profile["id"], "did:web:iriref.org");
    assert_eq!(profile["type"], json!(["Profile"]));
    assert!(!profile.to_string().contains("urn:secret"));
    canonicalize(&profile).unwrap();
    let err = source("urn:credential:issuer:name:nobody").unwrap_err();
    assert!(matches!(err, CoreError::NotFound(_)), "{err:?}");
}

#[test]
fn a_retired_key_still_verifies_what_it_signed_and_signs_nothing_new() {
    let store: Arc<MemoryAtoms> = Arc::default();
    let before = host_with(one_key(), store.clone(), true, NOW);
    let old = before.issued("e-1");
    // The key history after rotation: key-1 retired on 2027-01-01, key-2 in force.
    let rotated = config(vec![
        issuer_key("key-1", 7, KEY_1, Some("2027-01-01T00:00:00Z")),
        issuer_key("key-2", 9, KEY_2, None),
    ]);
    let after = host_with(rotated, store, true, LATER);
    let verdict = after.verify(&old, None);
    assert!(valid(&verdict), "{verdict}");
    let new = after.issued("e-2");
    assert_eq!(
        new["proof"]["verificationMethod"],
        "did:web:iriref.org#key-2"
    );
    assert!(valid(&after.verify(&new, None)));
}

#[test]
fn a_key_used_after_its_expiry_or_revoked_does_not_verify() {
    let host = host_with(one_key(), Arc::default(), true, LATER);
    let late = host.issued("e-1");
    let expired = config(vec![issuer_key(
        "key-1",
        7,
        KEY_1,
        Some("2027-01-01T00:00:00Z"),
    )]);
    let verdict = host_with(expired, Arc::default(), true, LATER).verify(&late, None);
    assert_eq!(
        verdict,
        "The credential is not valid: its issuer's key did:web:iriref.org#key-1 had expired at \
         2027-01-01T00:00:00Z, before its validFrom. Its status was not checked: status lists \
         are not built yet."
    );
    let mut revoked = one_key();
    revoked.issuers[0].keys[0].revoked = true;
    let verdict = host_with(revoked, Arc::default(), true, LATER).verify(&late, None);
    assert!(verdict.contains("was revoked"), "{verdict}");
}

#[test]
fn a_proof_by_a_key_that_is_not_the_issuers_does_not_verify() {
    let host = host();
    // Signed with a did:key the signer controls, but claiming iriref.org as its issuer.
    let mut credential = host.issued("e-1");
    let proof = credential.as_object_mut().unwrap().remove("proof").unwrap();
    let stranger = signing(13);
    let did = did_key_encode(&stranger.verifying_key());
    struct Key(SigningKey);
    impl Signer for Key {
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
            use ed25519_dalek::Signer as _;
            Ok(self.0.sign(message).to_bytes())
        }
    }
    let mk = did.trim_start_matches("did:key:");
    let options = ProofOptions {
        created: proof["created"].as_str().unwrap().into(),
        verification_method: format!("{did}#{mk}"),
        proof_purpose: "assertionMethod".into(),
    };
    let forged = issue(&credential, &options, &Key(stranger.clone())).unwrap();
    let verdict = host.verify(&forged, None);
    assert!(
        verdict.contains("belongs to did:key:")
            && verdict.contains("not to its issuer did:web:iriref.org"),
        "{verdict}"
    );
    // The same credential with the did:key as its issuer verifies: a did:key is its own key.
    credential["issuer"]["id"] = did.clone().into();
    let own = issue(&credential, &options, &Key(stranger)).unwrap();
    let verdict = host.verify(&own, None);
    assert!(valid(&verdict), "{verdict}");
}

#[test]
fn an_unknown_did_web_key_is_never_fetched() {
    let host = host();
    let mut credential = host.issued("e-1");
    credential["issuer"]["id"] = "did:web:elsewhere.example".into();
    credential["proof"]["verificationMethod"] = "did:web:elsewhere.example#key-1".into();
    let verdict = host.verify(&credential, None);
    assert!(
        verdict.contains("is not in this verifier's key history, and keys are never fetched"),
        "{verdict}"
    );
}

#[test]
fn a_changed_credential_does_not_verify_and_malformed_input_is_refused() {
    let host = host();
    let mut credential = host.issued("e-1");
    credential["name"] = "Advanced RDF".into();
    let verdict = host.verify(&credential, None);
    assert!(
        verdict.contains("does not match the issuer's key"),
        "{verdict}"
    );
    let request = Request::new(Verb::Source, Iri::parse(VERIFY).unwrap())
        .with_arg("in", ArgRef::Inline(b"not json".to_vec()));
    let err = host.run(request, &none()).unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument { ref name, .. } if name == "in"),
        "{err:?}"
    );
    let request = Request::new(Verb::Source, Iri::parse(VERIFY).unwrap())
        .with_arg("in", ArgRef::Inline(credential.to_string().into_bytes()))
        .with_arg("now", ArgRef::Inline(b"2026-11-27T12:00:00".to_vec()));
    let err = host.run(request, &none()).unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument { ref name, .. } if name == "now"),
        "{err:?}"
    );
}

#[test]
fn verify_takes_the_kernel_clock_when_no_clock_is_given() {
    let host = host();
    let mut credential = host.issued("e-1");
    credential.as_object_mut().unwrap().remove("proof");
    credential["validUntil"] = "2026-11-27T11:00:00Z".into();
    // Re-sign with the issuer's key so only the window is wrong.
    struct Key(SigningKey);
    impl Signer for Key {
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
            use ed25519_dalek::Signer as _;
            Ok(self.0.sign(message).to_bytes())
        }
    }
    let options = ProofOptions {
        created: "2026-11-27T10:00:00Z".into(),
        verification_method: "did:web:iriref.org#key-1".into(),
        proof_purpose: "assertionMethod".into(),
    };
    credential["validFrom"] = "2026-11-27T10:00:00Z".into();
    let secured = issue(&credential, &options, &Key(signing(7))).unwrap();
    let verdict = host.verify(&secured, None);
    assert!(
        verdict.contains("its validity period has ended"),
        "{verdict}"
    );
    let verdict = host.verify(&secured, Some("2026-11-27T10:30:00Z"));
    assert!(valid(&verdict), "{verdict}");
}

#[test]
fn a_bad_configuration_is_refused_with_a_sentence() {
    let mut bad = one_key();
    bad.issuers[0].did = "https://iriref.org".into();
    let err = space(bad, Arc::new(MemoryAtoms::default())).err().unwrap();
    assert_eq!(
        err.to_string(),
        "The issuer \"iriref\" must have a did:web identifier, not \"https://iriref.org\"."
    );
    let mut bad = one_key();
    bad.completion = "urn:learn:enrollment".into();
    let err = space(bad, Arc::new(MemoryAtoms::default())).err().unwrap();
    assert_eq!(
        err.to_string(),
        "The completion template \"urn:learn:enrollment\" has no {enrollment}; add it."
    );
}
