# Convo Safe implementation plan

## Repository and runtime

Use talos-hq/convo-safe as the independent home for Convo Safe. clud's multicall dispatcher recognizes executable aliases early and can expose a thin adapter later. Building the implementation into clud would tie its build and release to clud while Python still needs its own bindings. A standalone library also lets callers embed redaction without a process. Offer a JSON Lines stdio server for callers that want a process boundary. The caller can start one worker for multiple sessions without installing a system service or listener.

## Redaction and Keybox

- Detect provider credentials, credential assignments, private keys, bearer tokens, and the illustrated phone format. Prefer specific detectors over generic assignments and preserve surrounding text.
- Allocate monotonic session IDs and per-session content IDs in SQLite transactions. Deduplicate by type and exact secret text within the session.
- Store encrypted originals in Keybox using XChaCha20-Poly1305 and a caller-provisioned 32-byte key kept separately. Use a keyed fingerprint for lookup and authenticate record identity with associated data. Reopening with the same key must preserve sessions and mappings.
- Use explicit, versioned structured placeholders with type, session ID, and content ID. Authenticate placeholders and scope restoration to the requested session. Escape the marker prefix in literal input to preserve exact round trips.
- Expose session creation, get_or_create, redact, and restore in Rust, the Python extension, and the stdio server. Keep detailed input and original values out of error messages. Treat worker stdin/stdout as sensitive local channels.

## Validation and delivery

Test scanner boundaries, exact restoration, deduplication, cross-session isolation, reopen, wrong-key handling, concurrent access, and the server protocol. Build and smoke-test the PyPI wheel and sdist using the soldr backend. Publish to PyPI if the project can be authenticated and verify the public release. Land the repository through its configured GitHub policy. Supply no new workflow files.

## Streaming, sidecar replay, and detector coverage

OpenRouter's Sensitive Info Guardrail documents email, phone, SSN, card, IP,
person-name, and address presets for provider-bound inputs. It uses regex for
the first five and contextual NLP for the last two. Convo Safe will cover all
seven categories with deterministic patterns. Use explicit context and bounded
recognizable forms for names and addresses. Validate card checksums and IP
ranges to reduce false positives. Cover credentials separately, including
OpenRouter API keys, authorization headers, URL fields and common structured
assignment idioms. Validate these with adversarial fixtures developed
independently by category.

The worker accepts chunks for a logical message in a session and returns an
acknowledgment for each chunk. On message completion it redacts the assembled
text and emits it once, so private keys and other variable-length tokens can
span chunk boundaries. Bound pending bytes and output size. The same worker
can multiplex sessions.

Keep session mappings in an in-memory source when the worker is started with
`:memory:`. At session creation, create an encrypted SQLite replay database
next to the supplied session log. Append newly committed mappings after
redaction and explicit checkpoint operations, and seal the mirror at session
end. Acknowledge a successful checkpoint or return usable markers only after
the sidecar transaction commits. Mirror one session per file with its original
Keybox namespace and authenticated mapping identities. Permit trusted
read-only replay from that sidecar with the separately held master key.
