//! Interoperability with the Digital Credentials Consortium's `verifier-core` (JavaScript), in
//! both directions, offline. Three steps, run in this order by the CI job the pull request
//! names (Node is not a dev-dependency, so both Rust tests are `#[ignore]`d by default):
//!
//! 1. `export_for_dcc` writes, to `$IKIGAI_DCC_DIR`, a badge issued here, the unsigned badge,
//!    the issuer's `did:web` document, and the pinned contexts as ikigai-jsonld loads them.
//! 2. `node tests/dcc/run.mjs $IKIGAI_DCC_DIR` verifies the issued badge with `verifier-core`
//!    (and refuses a changed one), signs the unsigned badge with DCC's `eddsa-rdfc-2022` suite,
//!    and writes `dcc-signed.json`. Its `fetch` answers only from that directory.
//! 3. `a_badge_dcc_signs_verifies_here` verifies `dcc-signed.json` here, and refuses it changed.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use ikigai_credential::{issue, verify, ProofOptions, Signer, Verdict};
use ikigai_jsonld::PinnedContextLoader;
use ikigai_sign::multikey::multikey_encode;
use json_ld::{IriBuf, Loader};
use serde_json::{json, Value};
use std::path::PathBuf;

const ISSUER: &str = "did:web:iriref.org";
const METHOD: &str = "did:web:iriref.org#key-1";

/// The issuer's `did:web` document: one Multikey, for assertions.
fn did_document(public: &VerifyingKey) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": ISSUER,
        "verificationMethod": [{
            "id": METHOD,
            "type": "Multikey",
            "controller": ISSUER,
            "publicKeyMultibase": multikey_encode(public)
        }],
        "assertionMethod": [METHOD]
    })
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// An Open Badges 3.0 `OpenBadgeCredential`, every node with an id, as the issue Sink makes it.
fn badge() -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
        ],
        "id": "https://iriref.org/learn/student/id/s-7f3a/certificate/id/c-91d2",
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "name": "Introduction to RDF",
        "issuer": {
            "id": ISSUER,
            "type": ["Profile"],
            "name": "iriref.org",
            "url": "https://iriref.org/"
        },
        "validFrom": "2026-11-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "type": ["AchievementSubject"],
            "achievement": {
                "id": "urn:credential:achievement:course:rdf-intro:release:2026-1",
                "type": ["Achievement"],
                "name": "Introduction to RDF",
                "description": "Completed the course's exercises with evidence and met its mastery rules, self-paced.",
                "criteria": {
                    "id": "urn:credential:achievement:course:rdf-intro:release:2026-1:criteria",
                    "narrative": "Complete every unit's exercises and meet each unit's mastery rule."
                }
            }
        }
    })
}

struct Key(SigningKey);
impl Signer for Key {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn dir() -> PathBuf {
    PathBuf::from(
        std::env::var("IKIGAI_DCC_DIR").expect("IKIGAI_DCC_DIR names the exchange directory"),
    )
}

/// The context URLs the badges and the DID document name, all pinned in ikigai-jsonld.
const CONTEXTS: [&str; 3] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    "https://w3id.org/security/multikey/v1",
];

#[tokio::test]
#[ignore = "step 1 of the DCC job; needs IKIGAI_DCC_DIR"]
async fn export_for_dcc() {
    let dir = dir();
    std::fs::create_dir_all(dir.join("contexts")).unwrap();
    let write = |name: &str, value: &Value| {
        std::fs::write(dir.join(name), serde_json::to_vec_pretty(value).unwrap()).unwrap()
    };
    let signing = signing_key();
    let options = ProofOptions {
        created: "2026-11-27T00:00:00Z".into(),
        verification_method: METHOD.into(),
        proof_purpose: "assertionMethod".into(),
    };
    write(
        "issued.json",
        &issue(&badge(), &options, &Key(signing.clone())).unwrap(),
    );
    write("unsigned.json", &badge());
    write("did.json", &did_document(&signing.verifying_key()));
    let mut map = serde_json::Map::new();
    for (n, url) in CONTEXTS.iter().enumerate() {
        let iri = IriBuf::new(url.to_string()).unwrap();
        let document = PinnedContextLoader.load(&iri).await.unwrap();
        let text = document.document().to_string();
        let file = format!("contexts/{n}.json");
        std::fs::write(dir.join(&file), text).unwrap();
        map.insert(url.to_string(), file.into());
    }
    write("contexts.json", &Value::Object(map));
}

#[test]
#[ignore = "step 3 of the DCC job; needs IKIGAI_DCC_DIR/dcc-signed.json from tests/dcc/run.mjs"]
fn a_badge_dcc_signs_verifies_here() {
    let signed: Value =
        serde_json::from_slice(&std::fs::read(dir().join("dcc-signed.json")).unwrap()).unwrap();
    assert_eq!(
        signed["proof"]["cryptosuite"], "eddsa-rdfc-2022",
        "{signed:#}"
    );
    let public = signing_key().verifying_key();
    let check = |document: &Value| {
        verify(
            document.to_string().as_bytes(),
            "2026-11-27T12:00:00Z",
            |method, _| {
                assert_eq!(method, METHOD);
                Ok(public)
            },
        )
        .unwrap()
    };
    assert_eq!(check(&signed), Verdict::Valid, "{signed:#}");
    let mut changed = signed.clone();
    changed["name"] = "Advanced RDF".into();
    assert!(matches!(check(&changed), Verdict::Invalid(_)));
}
