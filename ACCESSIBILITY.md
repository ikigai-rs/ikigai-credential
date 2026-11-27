# Accessibility

How this repository approaches accessibility: what it emits that people read, the standard we
aim at, the evidence that exists today and what it does not cover, the barriers we know about,
and how to report one. It is a working agreement for contributors, maintainers and coding agents.
It is not a conformance claim, an Accessibility Conformance Report or a VPAT, and it is not legal
advice.

Adapted from the [ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md)
(MIT).

## Project information

| Field | Value |
|---|---|
| Project | ikigai-credential: a Rust library that issues and verifies verifiable credentials as ikigai resources |
| Published at | not published: a scaffold |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-credential/issues/new) |
| Private channel | [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-credential/security/advisories/new), for anything security-sensitive |
| Target | WCAG 2.2 Level AA, for any page or terminal that presents this output |
| Status | Evaluation in progress. No conformance claim. |
| Last reviewed | 2026-11-26 |
| Next review | when the crate first emits an error sentence, a verdict, the credential page or terminal text |

## Commitment

A credential is something a person shows to others: an employer, a colleague, a reviewer, any of
whom may use a screen reader, magnification or a keyboard alone. A credential page or a verdict
that carries its meaning only in a badge image, a check mark or a color keeps them from learning
what was attested. So every verdict will be a sentence that says what was checked and what was
found, the credential page will state in text what the credential attests and what it does not,
every value a person copies will have a labeled control of its own, and this file will say what
has not been tested.

## Scope

### In scope

- **Verification verdicts** (`Verdict::sentence`): one sentence that says what was checked and
  what was found, for example "The credential is not valid: its validity period has ended."
  Tested in `crates/ikigai-credential/tests/eddsa_rdfc_2022.rs` (`the_validity_window_is_checked`).
- **Refusal sentences** (`Error`): one sentence naming what was wrong and what to do, for example
  "The credential has a node without an id; give every node an id before issuing." Tested in the
  same file (`a_node_without_an_id_is_refused`). Date-time sentences name the field and the value
  and say what form is expected, for example "The credential is not valid: its validFrom
  \"2026-11-01T00:00:00\" has no timezone; a date-time stamp needs Z or an offset such as
  +02:00." Tested in the same file (`a_date_time_with_no_timezone_is_refused`). Sentences from JSON-LD expansion are passed
  through from the `json-ld` crate and are not yet rewritten into plain language.

Still planned: the public credential page with its in-browser Verify button and copy controls.

### Not ours to fix, still ours to report

The badge image and description an issuer supplies: the page can only carry the alternative text
the issuer wrote, and will show in text that it is missing rather than hide it. Other verifiers'
and wallets' presentation of a credential issued here.

## The rules that output follows

When output arrives, it follows the rules ikigai's other libraries follow: one sentence per
refusal that names what was wrong and what to do; no meaning carried by color, symbols or
alignment alone; no terminal control characters from untrusted input; American English.

## Conformance status

No conformance claim. There is no output to evaluate yet.

## Evidence

| Check | Result | Evidence |
|---|---|---|
| Refusal and verdict sentences pinned by tests | Blocked | the crate emits no refusal or verdict yet |
| Credential page checked in a browser and by an automated engine | Blocked | no credential page exists yet |
| Credential page read by a screen reader | Blocked | no credential page exists yet; no screen-reader session has been run |

**No screen reader or other assistive technology has been used to test this repository.**

## Known limitations

None known, because nothing is emitted yet.

## Contributor requirements

A pull request that adds output people read lists it under "In scope" above, pins it in a test,
and fills the pull request's `## Accessibility` section with a result for every check: Pass, Fail
or Blocked, with its evidence.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-credential/issues/new) and put "accessibility"
in its title. Useful details: what you were trying to do, what happened and what you expected,
whether you found a way around it, and your tools and any assistive technology, if you are
comfortable sharing them. You never need to disclose a disability. We aim to acknowledge within
7 days.

Anything security-sensitive, or anything you would rather not post publicly, goes through
[private vulnerability reporting](https://github.com/ikigai-rs/ikigai-credential/security/advisories/new).
If neither route works for you, say so in whichever you can reach and we will find another.

## Ownership and review

The maintainers of this repository own this file and review it whenever the crate first emits
output people read.

### Change history

- 2026-11-26: first version, for the scaffold.
- 2026-11-27: the date-time sentences for `validFrom`, `validUntil` and the verifier's clock.

## References

- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [ikigai-cli's ACCESSIBILITY.md](https://github.com/ikigai-rs/ikigai-cli/blob/main/ACCESSIBILITY.md), the model this file follows
