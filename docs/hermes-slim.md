# Hermes Slim redaction and resume integration

## Storage decision

Keep the durable transcript redacted and structurally valid. Plaintext logs
would bypass the same boundary that protects provider requests. The JSONL
projection keeps message roles, ordering, tool IDs, timestamps and safe
metadata queryable by standard tools. Store the encrypted Keybox sidecar next
to the log, and keep the master key in the profile's secret store. A read-only
export may restore verified references when explicitly requested. Never write
that export back to the canonical history or send it as model context.

Use the Hermes conversation lineage independently of its individual database
session IDs. A compression child inherits a consistent snapshot of the
parent's mappings. The original opaque strings stay valid even when Hermes
changes its session ID or copies a cached tail into a child. A new branch has
its own sidecar. Different values allocated in sibling branches at the same
content ID have different authenticated markers.

## Integration seams to wire

Verified against Hermes Slim commit
[9c4801f9714f](https://github.com/talos-hq/hermes-slim/tree/9c4801f9714f3e0a3411747bec42d3a9f08fa11a).

| Hermes Slim seam | Integration |
| --- | --- |
| `agent/turn_api_call.py`, provider request encoders, auxiliary calls including `agent/context_compressor.py` | Make the canonical model-visible record redacted before request encoding. Cover system and developer text, user turns, tool results, and structured tool arguments. Parse objects and visit text values before serialization. Retain typed protocol IDs and control fields. |
| Finalization, tool execution, streamed events and debug tracing | A stored model result may carry existing markers. Project complete text with `redact_model_text` before it becomes history or a diagnostic. Buffer variable-length fragments before exposure. Resolve references in the selected argument value immediately before trusted local tool execution. Redact tool output before it reaches the transcript or next provider request. |
| `hermes_state_messages.py` append, replace, rewind and `archive_and_compact` | Persist only the projection. Commit sidecar entries first. Preserve inactive rows for analysis and keep their mappings until history retention deletes the corresponding records. Do not restore then re-redact the cached prefix. |
| `hermes_state.py` JSONL fallback, gateway history and exports | Use the same redacted records across fallback, SQLite, and JSONL. Ordinary export and analytics receive redacted values. Explicit trusted replay uses bounded strict restore. |
| `hermes_state_compression.py::publish_compression_child` and session resume paths | Snapshot the parent sidecar before publishing the child, validate any markers in the summary and retained tail, and resolve the saved record against the matching sidecar before publishing the resumed session. Keep the prior active prefix if compaction fails. |

Redacting only the final request misses provider-side tool arguments,
auxiliary summarization and local logs. Redacting only the logger misses
provider traffic. Use a single projection at ingress with enforcement at the
durable and outbound sinks. Preserve the content bytes of the redacted
history across retries. Do not feed plaintext logs to the summarizer.

Hermes's existing request middleware falls back to the original request on
failure. Its `pre_api_request` observer also receives the original user text
and history. Put the privacy check before both paths and abort any protected
turn if the projector is unavailable or fails. Keep policy in an external
plugin and add only the enforcement and persistence contracts to Hermes core.

## Checkpoint and recovery protocol

1. Allocate an owner and a log path. Commit mappings and fsync the sidecar
   before committing a transcript record, then atomically publish the
   transcript revision using Hermes's session writer/lease. A crash before
   the record commit can leave unused encrypted mappings. They must never
   cause an old marker to refer to a different value.
2. A fresh process can reopen an unsealed sidecar with
   `Keybox.resume_replay(log, key)`. Check `replay_identity` against the
   saved lineage, then authenticate saved records using `validate_references`.
   Use bounded `restore_strict` for an explicitly trusted plaintext read.
   Send the original redacted record to the model. A sealed archive is
   read-only. Use `fork_replay(new_log)` and resume the new sidecar to continue
   an archive or create a compression child.
3. Store the logical conversation ID, sidecar path and owning numeric
   session ID together with the authenticated lineage identity in Hermes's
   durable session metadata. Bind the
   transcript revision to that metadata and reject an unexpected generation.
   Publish the sidecar before changing the active pointer. Reconcile a crash
   by reopening the last committed revision. Keep parent and child as one
   retention/export set until the child snapshot is verified independently.
4. A missing or wrong key, wrong scope, malformed marker after the full
   reserved prefix, or unauthenticated ciphertext stops strict replay.
   Hermes must also reject incomplete streams and truncated records, including
   a response cut off inside the marker prefix. Report a sanitized
   diagnostic and retain the old state. A fresh sidecar is staged with a
   private, unique filename and published atomically after the transaction
   commits. The profile directory needs a filesystem that supports hard links.
   Interrupted staging may leave an unreferenced .pending file that the
   recovery process can quarantine after confirming its writer has exited.
5. Do not split a logical text field into separately scanned fragments to fit
   a transport cap. Use the Python extension for complete large fields.
   Bound restored byte counts at the integration boundary. Provider summary
   size limits are independent. Reject or retry a summary with a truncated
   marker, and keep the previous valid context when retry is exhausted.

## Deployment gates

- Wire the projectors into every ingress, durable writer and outbound path
  listed above. Exercise CLI and gateway writes, JSONL database fallback,
  structured tool arguments/results, auxiliary calls, diagnostics and
  streaming before enabling the feature. Route binary media and opaque
  provider reasoning through a dedicated policy or reject them. The text
  scanner cannot establish that opaque artifacts are safe.
- Enable email redaction for a deployment that requires it. Supply typed
  mappings for secrets known to Hermes that have no reliable pattern. Run
  synthetic canaries across all allowed sinks to check for bypasses.
  Heuristics alone cannot prove detection of every unknown secret.
- Reopen real Hermes compression histories in an isolated test profile.
  Assert byte-identical model-visible input before and after restart,
  stable tool IDs, concurrent-write ordering, correct branch ancestry,
  bounded restore and independently analyzable JSON logs.
- Back up and restore a full exported log/sidecar pair against the retained
  key. Test partial snapshots, misplaced sidecars, corrupt records, profile
  changes, expired archives and a key lookup failure before rollout.
  Existing plaintext history requires an explicit migration and retention
  decision. Leave production history untouched during the pilot.

Convo Safe's native and installed-wheel tests exercise strict replay, writable
resume, sealed forks, branch isolation and a long synthetic compression
round trip. Hermes-side instrumentation is the next integration phase.
