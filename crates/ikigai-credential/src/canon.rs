//! A JSON-LD document to RDFC-1.0 canonical N-Quads, offline and in JSON-LD safe mode.
//!
//! Expansion and deserialization to RDF are the `json-ld` crate's, with ikigai-jsonld's
//! [`PinnedContextLoader`] (no network, contexts pinned by digest); RDFC-1.0 is
//! [`ikigai_rdf::canonicalize_dataset`]. Nothing here re-implements either standard.

use crate::Error;
use ikigai_jsonld::{PinnedContextLoader, JSON_LD_STACK};
use json_ld::expansion::{Action, Policy};
use json_ld::syntax::{Parse, Value};
use json_ld::{JsonLdProcessor, Options, RemoteDocument};
use oxrdf::{BlankNode, Dataset, GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use rdf_types::{Id, LiteralType};

/// JSON-LD safe mode: a term or IRI that does not expand to an absolute IRI is an error, never
/// dropped, so nothing a context does not define can pass unsigned or be signed unseen.
fn safe_mode() -> Policy {
    Policy {
        invalid: Action::Reject,
        vocab: Action::Reject,
        allow_undefined: false,
    }
}

/// Canonical N-Quads of `document`, which must already be bounded (see [`crate::parse_bounded`]).
pub(crate) fn canonical_nquads(document: &serde_json::Value) -> Result<String, Error> {
    let text = document.to_string();
    // Expansion recurses; give it the stack ikigai-jsonld sizes its own limits for.
    std::thread::Builder::new()
        .stack_size(JSON_LD_STACK)
        .spawn(move || futures::executor::block_on(canonical_nquads_now(&text)))
        .map_err(|e| {
            Error::Canonicalize(format!("The canonicalization thread could not start: {e}."))
        })?
        .join()
        .map_err(|_| Error::Canonicalize("Canonicalization stopped unexpectedly.".into()))?
}

async fn canonical_nquads_now(text: &str) -> Result<String, Error> {
    let (value, _) = Value::parse_str(text)
        .map_err(|e| Error::Input(format!("The document is not valid JSON: {e}.")))?;
    let input = RemoteDocument::new(None, None, value);
    let options = Options {
        expansion_policy: safe_mode(),
        ..Options::default()
    };
    let mut generator = rdf_types::generator::Blank::new();
    let mut rdf = input
        .to_rdf_full(
            (),
            &mut generator,
            &PinnedContextLoader,
            options,
            json_ld::warning::Print,
        )
        .await
        .map_err(|e| {
            Error::Input(format!(
                "The document could not be read as JSON-LD in safe mode: {e}. Use only terms the pinned contexts define."
            ))
        })?;
    let mut dataset = Dataset::new();
    for rdf_types::Quad(s, p, o, g) in rdf.cloned_quads() {
        let quad = Quad::new(subject(s)?, named(p.as_str())?, object(o)?, graph(g)?);
        dataset.insert(&quad);
    }
    let (nquads, _) = ikigai_rdf::canonicalize_dataset(&dataset).map_err(Error::Canonicalize)?;
    Ok(nquads)
}

fn named(iri: &str) -> Result<NamedNode, Error> {
    NamedNode::new(iri).map_err(|e| Error::Input(format!("The IRI {iri:?} is not valid: {e}.")))
}

fn blank(id: &str) -> Result<BlankNode, Error> {
    BlankNode::new(id.trim_start_matches("_:"))
        .map_err(|e| Error::Canonicalize(format!("A blank node label could not be used: {e}.")))
}

fn subject(id: Id) -> Result<NamedOrBlankNode, Error> {
    Ok(match id {
        Id::Iri(iri) => named(iri.as_str())?.into(),
        Id::Blank(b) => blank(b.as_str())?.into(),
    })
}

fn graph(id: Option<Id>) -> Result<GraphName, Error> {
    Ok(match id {
        None => GraphName::DefaultGraph,
        Some(Id::Iri(iri)) => named(iri.as_str())?.into(),
        Some(Id::Blank(b)) => blank(b.as_str())?.into(),
    })
}

fn object(term: rdf_types::Term) -> Result<Term, Error> {
    Ok(match term {
        rdf_types::Term::Id(id) => match subject(id)? {
            NamedOrBlankNode::NamedNode(n) => n.into(),
            NamedOrBlankNode::BlankNode(b) => b.into(),
        },
        rdf_types::Term::Literal(l) => match l.type_ {
            LiteralType::Any(datatype) => {
                Literal::new_typed_literal(l.value, named(datatype.as_str())?).into()
            }
            LiteralType::LangString(tag) => {
                Literal::new_language_tagged_literal(l.value, tag.as_str())
                    .map_err(|e| Error::Input(format!("A language tag is not valid: {e}.")))?
                    .into()
            }
        },
    })
}
