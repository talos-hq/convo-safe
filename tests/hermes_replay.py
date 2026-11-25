"""Exercise an installed Convo Safe build against a Hermes Slim checkout."""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from convo_safe import Keybox  # pylint: disable=import-error

MASTER = bytes(range(32))
PREFIX = "π" * 524_288 + " password="
PASSWORD = "hermes-replay-password-fixture"
EMAIL = "hermes-replay@example.org"


def write_parent(root, db):
    """Commit a projected parent record and its encrypted mappings."""
    box = Keybox(":memory:", MASTER)
    scope = box.create_session()
    projected = box.redact(scope, PREFIX + PASSWORD)
    assert projected.startswith(PREFIX) and PASSWORD not in projected
    box.checkpoint(scope, root / "parent.jsonl")
    db.create_session("parent", source="conformance")
    db.append_message("parent", "user", content=projected)
    (root / "expected-prefix.txt").write_text(projected, encoding="utf-8")


def compress_parent(root, db):
    """Publish a real Hermes compression child with a sidecar snapshot."""
    holder = f"conformance:pid={os.getpid()}"
    assert db.try_acquire_compression_lock("parent", holder)
    parent = Keybox.resume_replay(root / "parent.jsonl", MASTER)
    scope = parent.replay_session
    projected = db.get_messages("parent")[0]["content"]
    assert projected == (root / "expected-prefix.txt").read_text(encoding="utf-8")
    assert parent.redact_model_text(scope, projected) == projected
    marker = projected.removeprefix(PREFIX)
    summary = parent.redact_model_text(
        scope, f"Remember {marker}; reply to {EMAIL}", redact_email=True
    )
    assert marker in summary and EMAIL not in summary
    parent.fork_replay(root / "child.jsonl")
    parent.fork_replay(root / "sibling.jsonl")
    child = Keybox.open_replay(root / "child.jsonl", MASTER)
    binding = {
        "lineage": child.replay_identity,
        "sidecar": child.replay_sidecar_id,
    }
    assert all(binding.values())
    assert_stale_lease_keeps_parent(db, parent, projected, summary, binding)
    db.publish_compression_child(
        parent_session_id="parent",
        child_session_id="child",
        source="conformance",
        messages=[{"role": "user", "content": summary}],
        model_config={"replay_binding": binding},
        compression_lock_holder=holder,
    )
    parent.seal_replay()
    (root / "expected-summary.txt").write_text(summary, encoding="utf-8")


def assert_stale_lease_keeps_parent(db, parent, projected, summary, binding):
    """A rejected publish must leave the parent active and its sidecar writable."""
    from hermes_state_errors import (  # pylint: disable=import-error,import-outside-toplevel
        CompressionSessionBusyError,
    )

    try:
        db.publish_compression_child(
            parent_session_id="parent",
            child_session_id="child",
            source="conformance",
            messages=[{"role": "user", "content": summary}],
            model_config={"replay_binding": binding},
            compression_lock_holder="stale-holder",
        )
    except CompressionSessionBusyError:
        pass
    else:
        raise AssertionError("compression publication accepted a stale lease")
    assert db.resolve_resume_session_id("parent") == "parent"
    assert db.get_session("child") is None
    assert db.get_messages("parent")[0]["content"] == projected
    assert "orphan-fixture" not in parent.redact(
        parent.replay_session, "password=orphan-fixture"
    )


def resume_child(root, db):
    """Verify exact redacted and restored records after another process restart."""
    tip = db.resolve_resume_session_id("parent")
    assert tip == "child"
    child = Keybox.resume_replay(root / "child.jsonl", MASTER)
    scope = child.replay_session
    summary = db.get_messages(tip)[0]["content"]
    binding = db.get_session_model_config_value(tip, "replay_binding")
    assert binding == {
        "lineage": child.replay_identity,
        "sidecar": child.replay_sidecar_id,
    }
    sibling = Keybox.open_replay(root / "sibling.jsonl", MASTER)
    assert sibling.replay_sidecar_id != binding["sidecar"]
    assert sibling.replay_identity == child.replay_identity
    sibling.validate_references(scope, summary)
    projected = db.get_messages("parent")[0]["content"]
    assert summary == (root / "expected-summary.txt").read_text(encoding="utf-8")
    assert projected == (root / "expected-prefix.txt").read_text(encoding="utf-8")
    assert child.redact_model_text(scope, summary) == summary
    assert child.redact_model_text(scope, projected) == projected
    assert child.restore_strict(scope, summary, 1024) == (
        f"Remember {PASSWORD}; reply to {EMAIL}"
    )
    assert child.restore_strict(scope, projected, 2**21) == PREFIX + PASSWORD
    for path in root.glob("state.db*"):
        assert PASSWORD.encode() not in path.read_bytes(), path.name
        assert EMAIL.encode() not in path.read_bytes(), path.name


PHASES = {"write": write_parent, "compress": compress_parent, "resume": resume_child}


def main():
    """Exercise write, compaction, and resume in separate interpreters."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=PHASES)
    args = parser.parse_args()
    if args.phase:
        # Import after the child inherits the isolated profile.
        from hermes_state import SessionDB  # pylint: disable=import-error,import-outside-toplevel

        root = Path(os.environ["HERMES_HOME"])
        db = SessionDB(db_path=root / "state.db")
        try:
            PHASES[args.phase](root, db)
        finally:
            db.close()
        return
    with TemporaryDirectory() as scratch:
        env = {
            **os.environ,
            "HERMES_HOME": scratch,
            "HERMES_RUNTIME_DIR": str(Path(scratch, "runtime")),
        }
        script = Path(__file__).resolve()
        for phase in PHASES:
            subprocess.run(
                [sys.executable, script, "--phase", phase], env=env, check=True
            )
    print("Hermes SQLite replay passed across three processes")


if __name__ == "__main__":
    main()
