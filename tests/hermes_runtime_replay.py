"""Run the installed-wheel replay check through Hermes's protected runtime."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from convo_safe import Keybox  # pylint: disable=import-error
from hermes_replay import (
    EMAIL,
    MASTER,
    PASSWORD,
    PREFIX,
    publish_child,
    run_isolated_phases,
)


def write_parent(db):
    """Initialize and persist an unprojected long user turn through Hermes."""
    db.create_protected_session(
        "parent", "conformance", system_prompt=f"Reply to {EMAIL}"
    )
    db.append_message("parent", "user", content=PREFIX + PASSWORD)
    assert EMAIL not in db.get_session("parent")["system_prompt"]
    assert PASSWORD not in db.get_messages_as_conversation("parent")[0]["content"]


def compress_parent(db):
    """Rotate the live redacted prefix under Hermes's compression lease."""
    from agent.protected_request import (  # pylint: disable=import-error,import-outside-toplevel
        project_request,
        protected_child_config,
        session_request_keybox,
    )

    projected = db.get_messages_as_conversation("parent")[0]["content"]
    box = session_request_keybox(db, "parent")
    payload = project_request(
        box,
        {
            "messages": [{"role": "user", "content": projected}],
            "instructions": f"Reply to {EMAIL}",
        },
    )
    assert payload["messages"][0]["content"] == projected
    assert EMAIL not in payload["instructions"]
    summary = summarize_for_rotation(db, projected)
    holder = f"conformance:pid={os.getpid()}"
    assert db.try_acquire_compression_lock("parent", holder)
    publish_child(
        db,
        holder,
        summary,
        protected_child_config(db, "parent", "child", {}),
        system_prompt=payload["instructions"],
    )


def summarize_for_rotation(db, projected):
    """Use the real auxiliary boundary with a synthetic provider response."""
    from agent.context_compressor import (  # pylint: disable=import-error,import-outside-toplevel
        ContextCompressor,
    )

    marker = projected.removeprefix(PREFIX)

    def respond(**kwargs):
        prompt = kwargs["messages"][0]["content"]
        assert marker in prompt and PASSWORD not in prompt and EMAIL not in prompt
        response = SimpleNamespace(
            content=f"Remember {marker}; reply to {EMAIL}", reasoning_content=None
        )
        return SimpleNamespace(
            choices=[SimpleNamespace(finish_reason="stop", message=response)]
        )

    with patch(
        "agent.context_compressor.get_model_context_length", return_value=100_000
    ):
        compressor = ContextCompressor(model="test", quiet_mode=True)
    compressor.bind_session_state(db, "parent")
    with patch("agent.context_compressor.call_llm", side_effect=respond):
        summary = compressor._call_summary_llm(  # pylint: disable=protected-access
            f"Summarize {projected}; reply to {EMAIL}", 0.0
        )
    assert len(summary) < 1024 and EMAIL not in summary
    return summary


def resume_child(db):
    """Ensure the restarted model history matches what the parent stored."""
    from agent.protected_request import session_request_keybox  # pylint: disable=import-error,import-outside-toplevel

    assert db.resolve_resume_session_id("parent") == "child"
    parent = db.get_messages_as_conversation("parent")[0]["content"]
    history, display = db.get_resume_conversations("child")
    marker = parent.removeprefix(PREFIX)
    assert marker in history[0]["content"] and EMAIL not in history[0]["content"]
    box = session_request_keybox(db, "child")
    assert box.restore_strict(box.replay_session, parent, 2**21) == PREFIX + PASSWORD
    assert box.restore_strict(box.replay_session, history[0]["content"], 2048) == (
        f"Remember {PASSWORD}; reply to {EMAIL}"
    )
    assert any(row["content"] == parent for row in display)
    assert PASSWORD not in parent


def recover_offline(root):
    """Exercise the real JSONL diversion once the SQLite database is offline."""
    from hermes_state import divert_session_transcript_jsonl  # pylint: disable=import-error,import-outside-toplevel

    db_path = root / "state.db"
    db_path.rename(root / "offline-state.db")
    fallback = divert_session_transcript_jsonl(
        "child", [{"role": "user", "content": PREFIX + PASSWORD}]
    )
    text = fallback.read_text(encoding="utf-8")
    assert PASSWORD not in text
    box = Keybox.open_replay(fallback, MASTER)
    record = json.loads(text)
    assert (
        box.restore_strict(box.replay_session, record["content"], 2**21)
        == PREFIX + PASSWORD
    )
    for path in root.glob("*state.db*"):
        assert PASSWORD.encode() not in path.read_bytes()
        assert EMAIL.encode() not in path.read_bytes()


PHASES = {"write": write_parent, "compress": compress_parent, "resume": resume_child}


def check_restored_resume(root, *, key=MASTER, expect_failure=False):
    """Check a relocated profile in a fresh process with independent config."""
    env = {
        **os.environ,
        "HERMES_HOME": str(root),
        "HERMES_RUNTIME_DIR": str(root / "runtime"),
        "HERMES_CONVO_SAFE_MASTER_KEY": key.hex() if key is not None else "",
    }
    phase = "reject-resume" if expect_failure else "resume"
    subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--phase", phase],
        env=env,
        check=True,
        timeout=120,
    )


def check_profile_backup(root):
    """Restore a quiescent profile and reject incomplete or mismatched copies."""
    from hermes_state_replay import replay_log_path  # pylint: disable=import-error,import-outside-toplevel

    with TemporaryDirectory() as directory:
        restored = Path(directory) / "restored"
        shutil.copytree(root, restored)
        check_restored_resume(restored)
        check_restored_resume(restored, key=None, expect_failure=True)
        check_restored_resume(restored, key=bytes([1]) * 32, expect_failure=True)
        parent_log = replay_log_path(restored / "state.db", "parent")
        child_log = replay_log_path(restored / "state.db", "child")
        parent = parent_log.with_name(parent_log.name + ".keybox.sqlite")
        child = child_log.with_name(child_log.name + ".keybox.sqlite")
        saved = child.with_suffix(".saved")
        child.rename(saved)
        check_restored_resume(restored, expect_failure=True)
        shutil.copyfile(parent, child)
        check_restored_resume(restored, expect_failure=True)
        child.write_bytes(b"corrupt sidecar")
        check_restored_resume(restored, expect_failure=True)
        saved.replace(child)
        check_restored_resume(restored)


def run_phase(phase):
    """Open runtime state only in the isolated child process."""
    from hermes_state import SessionDB  # pylint: disable=import-error,import-outside-toplevel
    from hermes_state_replay import ProtectedReplayError  # pylint: disable=import-error,import-outside-toplevel

    root = Path(os.environ["HERMES_HOME"])
    if phase == "backup":
        check_profile_backup(root)
        return
    if phase == "offline":
        recover_offline(root)
        return
    with SessionDB(db_path=root / "state.db") as db:
        if phase == "reject-resume":
            try:
                resume_child(db)
            except ProtectedReplayError:
                return
            raise AssertionError("Resume accepted a damaged profile backup")
        PHASES[phase](db)


def main():
    """Exercise restart, backup relocation and offline recovery in fresh processes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase", choices=(*PHASES, "backup", "reject-resume", "offline")
    )
    args = parser.parse_args()
    if args.phase:
        run_phase(args.phase)
        return
    run_isolated_phases(
        Path(__file__).resolve(),
        (*PHASES, "backup", "offline"),
        extra_env={"HERMES_CONVO_SAFE_MASTER_KEY": MASTER.hex()},
    )
    print("Hermes runtime replay, profile backup, and offline recovery passed")


if __name__ == "__main__":
    main()
