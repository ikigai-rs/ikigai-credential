# ikigai-credential

Verifiable credentials as resources for [ikigai](https://github.com/ikigai-rs): issue and verify
[W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/) in the
[Open Badges 3.0](https://www.imsglobal.org/spec/ob/v3p0) profile, secured with
[Data Integrity](https://www.w3.org/TR/vc-data-integrity/) `eddsa-rdfc-2022`, so a credential anyone
can check is also a graph a kernel can query.

The format is one format: an `OpenBadgeCredential` (which is a VC 2.0), with an `eddsa-rdfc-2022`
proof. The document and the proof configuration are canonicalized with RDFC-1.0, hashed with
SHA-256, and signed with Ed25519 by [ikigai-sign](https://github.com/ikigai-rs/ikigai-sign); keys
are Multikey and the signature is base58-btc multibase. No JWT form, and no selective-disclosure
suite for issuing. Verifying `ecdsa-sd-2023` comes later.

Status: **the cryptosuite core and the five resources are built; the rest is not.** The crate
issues and verifies `eddsa-rdfc-2022` proofs over Open Badges 3.0 credentials (`issue`, `verify`),
offline and in JSON-LD safe mode, pinned by the W3C EdDSA vectors, and `resource::space` binds the
issuer, achievement, credential, issue and verify resources below, signing through ikigai-sign's
`urn:sign:sign` and writing one ikigai-log entry per issuance. A badge issued here verifies in
SpruceID's `ssi`, and one `ssi` signs verifies here (`tests/independent_ssi.rs`, offline), and the
same holds both ways with the Digital Credentials Consortium's `verifier-core`, including its Open
Badges 3.0 JSON Schema check (`tests/dcc/`, the `dcc-verifier-core` CI job, offline). Still
planned: a vendored 1EdTech example, a persistent IRI minted through ikigai-name (ikigai-name 0.9.0 has no minting resource,
so the host's template is expanded directly), the status lists (ledger #4146), the page (ledger #4147) and several issuers (ledger
#4159).

## The resource map

Names are singular, the type first, and every partition is by a named key. The first five are
built (`resource::space`); the page and the status resources are planned.

| Name | What it is |
|---|---|
| `urn:credential:issuer:name:{i}` | an issuer: the Open Badges `Profile` (name, URL, a `did:web` identifier). An open Source. Its key lives in ikigai-secret, never in this module |
| `urn:credential:achievement:course:{c}:release:{r}` | the `Achievement` for a course release (name, description, criteria, alignment, image), composed from whatever describes that release, read through the kernel. An open Source |
| `urn:credential:issue:enrollment:{n}` | the issue Sink, requiring `urn:cap:credential:issue`, `urn:cap:sign` and `urn:cap:log:write`. Sealed: it refuses (Conflict) unless the enrollment's completion rule holds, and once the enrollment has its credential; it signs through `urn:sign:sign`, and answers the new atom's name (`text/uri-list`); it writes one `urn:log:write` entry per issuance (who, the enrollment, the credential's IRI; never the subject). Planned: it assigns a status-list index, and gives the credential a persistent IRI through ikigai-name once that offers a minting resource |
| `urn:credential:id:{id}` | a credential: an atom, written once by the issue Sink and never changed. A Source requiring `urn:cap:credential:read` |
| `urn:credential:id:{id}:form:page` | the credential's public page (planned below) |
| `urn:credential:verify` | the verifier: an open Source. A credential in, a verdict sentence out: the proof, that the proof's key belongs to the issuer, the issuer's key as of `validFrom`, the validity window, and (planned) the status read current |
| `urn:credential:status:list:{l}` | a Bitstring Status List credential, one per purpose per issuer |
| `urn:credential:status:credential:{id}:purpose:{p}` | the Sinks that revoke (permanent) or suspend (reversible) one credential |

### Configuration

The host gives `resource::Config`: its issuers (name, display name, URL, `did:web` identifier, the
template a credential's public `id` comes from, and the key history: each key's Multikey, the IRI
of its private key in ikigai-secret, the scopes reading it needs, and `expires` once retired), and
two IRI templates the module reads through the kernel: the description of a course release
(`{course}`, `{release}`) and an enrollment's completion (`{enrollment}`: whether the rule holds,
the issuer, course, release and the opaque student id). Issued credentials are kept by an
`AtomStore` the host supplies; `MemoryAtoms` keeps them in memory.

## Requirements the design holds to

- **No network at issue or verify time.** The VC 2.0, Data Integrity and Open Badges contexts are
  pinned locally by digest (in ikigai-jsonld, the shared home), and documents are processed in
  JSON-LD safe mode.
- **No blank nodes.** The credential, achievement, issuer and evidence each get an id.
- **No identifier that joins a person's credentials.** The subject is the holder's chosen display
  name plus either a `did:key` they control or a salted, hashed email (the Open Badges identity
  object), never an identifier we mint. Evidence is only what the holder chooses to make public.
- **Say what it attests.** The page states what the credential attests and what it does not (for
  example: completed the course's exercises with evidence and met its mastery rules, self-paced; not
  an identity-proofed exam).
- **Logs, not payloads.** Issuance and revocation are logged and attributed in ikigai-log; the
  credential carries only its proof. A revocation's reason goes to the log, never into the list.
  The entry's class and columns are declared in `src/vocabulary.ttl`, under
  `https://ikigai-rs.dev/ns/credential#` (`VOCABULARY_TTL`), which a host that logs passes to
  ikigai-log's `Vocabulary::extend`.
- **Bounded input.** JSON-LD nesting depth is bounded before any request input is parsed.

## Status lists (planned, ledger #4146)

[Bitstring Status List 1.0](https://www.w3.org/TR/vc-bitstring-status-list/): at least 131,072
entries per list for herd privacy, indexes assigned at random, GZIP through ikigai-compress,
re-signed on every change, served so caches sit in front and the issuer cannot see who checks whom.
The list's URL is a persistent IRI, because it is signed into every credential. A credential is
revoked for error or misconduct only.

## The credential page (planned, ledger #4147)

An accessible public page per credential (WCAG 2.2 AA, evaluated, never claimed): who, what, when,
the criteria, the evidence the holder chose to show, the JSON-LD embedded, a download, and a Verify
button that runs the verifier in the browser on the wasm kernel, so nothing on our side logs who
checked whom. For adding it to a professional profile, the page gives the five fields such a profile
asks for (name, issuing organization, issue date, credential ID, credential URL), each labeled and
each with its own copy button. No analytics, no cookies, no stored addresses.

## Several issuers in one host (planned, ledger #4159)

Each issuer has its own `did:web` identifier, key, key history and status lists, and an issuer's
capability never reaches another issuer's key or lists. A retired key stays in the issuer's
`did:web` document with `expires` set and is never removed; it is marked `revoked` only on
compromise.

## Done means interoperable

A credential issued here verifies in an independent verifier, and one issued elsewhere verifies
here, both from the W3C and 1EdTech vectors, in CI with no network: SpruceID's `ssi` (Rust) and the
Digital Credentials Consortium's `verifier-core` (JavaScript).

## Related

- [ikigai-learn](https://github.com/ikigai-rs/ikigai-learn): courses whose completed releases these
  credentials attest.
- [ikigai-sign](https://github.com/ikigai-rs/ikigai-sign): the Ed25519 signatures the proofs use.

## Accessibility

See [ACCESSIBILITY.md](ACCESSIBILITY.md): the target (WCAG 2.2 AA), the evidence that exists, what
has not been tested, and how to report a barrier.

## License

MIT OR Apache-2.0.
