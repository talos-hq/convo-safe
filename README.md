# Convo Safe

Convo Safe replaces recognizable secrets in prompts with typed placeholders and
stores the originals in an encrypted local Keybox. A trusted replay can restore
the original text after a process restart.

## Install

```sh
python -m pip install convo-safe
```

The wheel installs the `convo_safe` Python module and the native `convo-safe`
worker executable.

## Python

```python
from pathlib import Path

from convo_safe import Keybox, SecretType

# Load a high-entropy 32-byte key kept separately from the database.
box = Keybox("replay.sqlite", Path("keybox.key").read_bytes())
session = box.create_session()
prompt = "Please call (555)124-4856."
redacted = box.redact(session, prompt)
assert "(555)124-4856" not in redacted
assert box.restore(session, redacted) == prompt
placeholder = box.get_or_create(session, SecretType.PHONE, "(555)124-4856")
assert placeholder in redacted
```

Store the session ID with the replay. Reuse it across turns in the same conversation.
For independent replay, call `box.checkpoint(session, "turns.jsonl")` as the
log grows and `box.finalize_replay(session, "turns.jsonl")` when the session
ends. A trusted reader can load the sidecar using
`Keybox.open_replay("turns.jsonl", master_key)`.

Automatic email redaction is opt-in. Use
`box.redact(session, prompt, redact_email=True)` to replace full email
addresses. The default leaves email text available to your own fuzzy
matching or masking rules. Explicit `get_or_create` mappings and replay work
regardless of the detector setting.

In Rust the same operations are available through `convo_safe::Keybox`
and `convo_safe::SecretType`. Use `Keybox::redact_with_options` with
`RedactionOptions { redact_email: true }` to enable email detection. Set `default-features = false` to embed the
library without the worker's JSON dependency.

## Local worker

Create a key once with `convo-safe init-key KEY_FILE`. Start the worker as a
child process using `convo-safe serve :memory: KEY_FILE`. Keep its pipes
private. Provide a database path instead of `:memory:` to persist the source
Keybox and allocate increasing session IDs across worker restarts.

On Unix the worker creates a mode-0600 key file and checks that other users
and groups have no access. On Windows, put it in a directory with a private
ACL. Store the key separately from the database and session logs.

Send UTF-8 JSON Lines over stdin. For example, this exchange buffers a phone
number across transport chunks and emits a redacted message after the caller
marks the logical message complete.

| Request | Success response |
| --- | --- |
| `{"op":"create_session","session_log":"turns.jsonl"}` | `{"session":1}` |
| `{"op":"begin_message","session":1}` | `{"ok":true}` |
| `{"op":"chunk","session":1,"text":"Call (555)124-"}` | `{"ok":true}` |
| `{"op":"chunk","session":1,"text":"4856"}` | `{"ok":true}` |
| `{"op":"finish_message","session":1}` | `{"text":"Call ..."}` |
| `{"op":"end_session","session":1}` | `{"ok":true}` |

Use `"redact_email": true` in `create_session` to enable email
detection for that worker session, including streamed messages.

Send one stream at a time per session. Use `abort_message` to discard a
partial message. An oversized chunk also discards the buffered message. Use `redact` with a complete `text` for one-shot use, or
`get_or_create` with `kind` and `secret` to mark a known value. Each takes
`session`. The worker accepts up to 1 MiB of text per logical message.
Requests over the 8 MiB frame limit end the worker. Failures return
`{"error":"..."}`. Treat a failed redaction as a failed send.

The worker adds encrypted mappings to `turns.jsonl.keybox.sqlite` before
returning markers. `checkpoint` syncs any outstanding mappings. `end_session`
seals the mirror and closes that session. EOF also seals open sessions and
discards unfinished messages. The caller owns the transcript and can log the
returned text after the worker acknowledges it. A different agent with access
to the sidecar and key can run `convo-safe replay turns.jsonl KEY_FILE` and send
`{"op":"restore","session":1,"text":"..."}`. Regular workers accept restore
only when started with `--allow-restore`.

For a Rust-only install, build with
`soldr cargo build --locked --bin convo-safe`.

## Placeholder handling

A placeholder looks like
`[[CONVO_SAFE:v1:{"REDACTED":"PHONE","SESSIONID":1,"CONTENTID":1,"TAG":"…"}]]`.
The tag authenticates the type and IDs within the originating Keybox. IDs
increase within their scope, and equal types and values within a session share
a placeholder. Keep markers byte-for-byte unchanged for restoration.

Suggested model instruction:

> CONVO_SAFE placeholders represent values already withheld locally. Preserve
> any placeholder you need to reference verbatim. Continue the task with the
> placeholders in place. A placeholder alone does not indicate exposure of
> the original value or require a rotation notice.

The scanner recognizes common provider tokens, private-key blocks, Basic and
Bearer credentials, credential assignments, URL passwords and query values,
and YAML secret scalars. It detects North American phone numbers, explicit
international phone shapes, formatted SSNs, checksum-valid card numbers,
IPv4 and IPv6, and common contextual forms for personal names and street
addresses. Phone detections include common extension syntax. Labelled ABA
routing numbers need a valid check digit. Bank and checking/savings account
numbers need banking context. Email detection, when enabled, covers common
dot-atom addresses, plus aliases, and internationalized labels.

OpenRouter's documented sensitive-info presets cover email, phone, SSN,
credit card, IP address, secrets, person name, and address. Its preset and
custom-regex filters can redact or block provider-bound text. The local
scanner uses deterministic patterns and does not implement OpenRouter's
hosted contextual NLP. The test corpus links the sample datasets and describes
which cases are covered.
[OpenRouter presets](https://openrouter.ai/docs/guides/features/guardrails/sensitive-info) ·
[Secret formats](https://openrouter.ai/docs/guides/features/guardrails/secret-formats) ·
[Fixture provenance](tests/fixtures/README.md)

Scan each logical text field before putting it into the provider's request
structure. This preserves JSON framing for messages or tool arguments.

The Keybox stores authenticated ciphertext and deduplication fingerprints.
Session IDs, content IDs, categories, and ciphertext lengths are visible in its
database. Losing the master key prevents replay. Keep original prompts and
restoration output on the trusted side of the application.

## Resuming archived conversations

Use the Python extension to continue an unsealed sidecar with
`Keybox.resume_replay(log, master_key)`. Its `replay_session` property supplies
the owning session ID. `seal_replay()` finalizes that sidecar and prevents
later appends. A trusted reader can fork a saved sidecar with
`fork_replay(new_log)` and resume the new path. Existing parent markers survive
the fork. Divergent mappings remain branch-local.

Use `redact_model_text` for model responses containing authentic existing
markers. Ordinary `redact` escapes literal marker syntax in fresh raw text.
Use `restore_strict(session, text, max_bytes)` when a saved record must contain
only valid, resolvable markers.

See the [Hermes Slim integration plan](docs/hermes-slim.md) for transcript
projection, compression boundaries and deployment checks.

## Build and validate

Run the local Linux gate with `python3 ci/gate.py`. It runs Rust and Python
lint, Rust integration tests, and a smoke test of the installed native wheel.

Run `python3 ci/wheel.py release` to stage a source archive and a Linux x86-64
wheel in `dist/release`. The release gate checks the glibc 2.17 floor and tests
the installed worker on Python 3.10 and 3.14. The Rust package is internal to
the Python app while its API and crate layout stabilize.

A manual run of `auto-release.yml` stages artifacts for review. A new version
tag on main, matching both package manifests, publishes the staged artifacts
to PyPI through the `pypi` environment.
