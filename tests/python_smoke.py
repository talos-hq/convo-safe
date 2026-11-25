"""Exercise the package and native worker after installing the built wheel."""

import json
import re
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from convo_safe import Keybox, SecretType


def main():
    """Verify Python redaction and replay through the packaged worker."""
    with TemporaryDirectory() as scratch:
        root = Path(scratch)
        key_file = root / "keybox.key"
        log = root / "turns.jsonl"
        subprocess.run(["convo-safe", "init-key", key_file], check=True)
        master = key_file.read_bytes()
        box = Keybox(":memory:", master)
        session = box.create_session()
        original = "Call (555)124-4856 or email fixture@example.org."
        assert "fixture@example.org" in box.redact(session, original)
        redacted = box.redact(session, original, redact_email=True)
        assert "(555)124-4856" not in redacted
        assert "fixture@example.org" not in redacted
        assert box.get_or_create(session, SecretType.PHONE, "(555)124-4856") in redacted
        box.checkpoint(session, log)
        assert Keybox.open_replay(log, master).restore(session, redacted) == original
        box.finalize_replay(session, log)
        request = json.dumps({"op": "restore", "session": session, "text": redacted})
        result = subprocess.run(
            ["convo-safe", "replay", log, key_file],
            input=f"{request}\n",
            text=True,
            capture_output=True,
            check=True,
        )
        assert json.loads(result.stdout) == {"text": original}


def worker_round_trip(worker, request):
    """Send one JSONL worker request and read its response."""
    assert worker.stdin is not None and worker.stdout is not None
    worker.stdin.write(json.dumps(request) + "\n")
    worker.stdin.flush()
    return json.loads(worker.stdout.readline())


def test_chat_replay():
    """Exercise multiple outbound and mock assistant turns through the worker."""
    cases = json.loads(
        (Path(__file__).parent / "fixtures" / "chats.json").read_text(encoding="utf-8")
    )
    with TemporaryDirectory() as scratch:
        root = Path(scratch)
        key = root / "keybox.key"
        log = root / "agent.jsonl"
        default_log = root / "default.jsonl"
        subprocess.run(["convo-safe", "init-key", key], check=True)
        with subprocess.Popen(
            ["convo-safe", "serve", ":memory:", key],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        ) as worker:
            session = worker_round_trip(
                worker,
                {
                    "op": "create_session",
                    "session_log": str(log),
                    "redact_email": True,
                },
            )["session"]
            other = worker_round_trip(
                worker,
                {
                    "op": "create_session",
                    "session_log": str(default_log),
                },
            )["session"]
            default = worker_round_trip(
                worker,
                {
                    "op": "redact",
                    "session": other,
                    "text": cases[1]["message"],
                },
            )["text"]
            assert cases[1]["secrets"]["EMAIL"] in default
            assert cases[1]["secrets"]["PHONE"] not in default
            replies = [mock_reply(worker, session, case) for case in cases]
            assert worker_round_trip(
                worker, {"op": "end_session", "session": session}
            ) == {"ok": True}
            assert worker_round_trip(
                worker, {"op": "end_session", "session": other}
            ) == {"ok": True}
            assert worker.stdin is not None
            worker.stdin.close()
            assert worker.wait(timeout=10) == 0
        replay = Keybox.open_replay(log, key.read_bytes())
        isolated = Keybox.open_replay(default_log, key.read_bytes())
        for reply, expected in replies:
            assert replay.restore(session, reply) == expected
            assert isolated.restore(other, reply) == reply
        assert replies[0][0].split(" | ")[0] == replies[2][0].split(" | ")[-1]


def mock_reply(worker, session, case):
    """Return only the opaque references a provider would see."""
    redacted = worker_round_trip(
        worker,
        {
            "op": "redact",
            "session": session,
            "text": case["message"],
        },
    )["text"]
    markers = re.findall(r"\[\[CONVO_SAFE:v1:(\{[^}]+\})\]\]", redacted)
    kinds = [json.loads(marker)["REDACTED"] for marker in markers]
    secrets = case["secrets"]
    assert len(kinds) == len(secrets) and set(kinds) == set(secrets)
    assert all(value not in redacted for value in secrets.values())
    return (
        " | ".join(f"[[CONVO_SAFE:v1:{marker}]]" for marker in markers),
        " | ".join(secrets[kind] for kind in kinds),
    )


def test_long_compressed_resume():
    """Keep a long model-visible prefix stable across compression and restart."""
    with TemporaryDirectory() as scratch:
        transcript = Path(scratch, "session.jsonl")
        child_log = transcript.with_name("compressed.jsonl")
        master = bytes(range(32))
        source = Keybox(":memory:", master)
        session = source.create_session()
        original = "π" * 524_288 + " password=long-message-fixture"
        projected = source.redact(session, original)
        source.checkpoint(session, transcript)
        del source
        transcript.write_text(
            json.dumps({"role": "user", "content": projected}, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )

        saved = Keybox.resume_replay(transcript, master)
        assert saved.replay_session == session
        identity = saved.replay_identity
        assert identity is not None
        [marker] = re.findall(r"\[\[CONVO_SAFE:v1:\{[^}]+\}\]\]", projected)
        summary = saved.redact_model_text(
            session,
            f"Keep {marker}; beneficiary: fixture@example.org",
            redact_email=True,
        )
        assert marker in summary and "fixture@example.org" not in summary
        saved.seal_replay()
        saved.fork_replay(child_log)
        child_log.write_text(
            json.dumps({"role": "system", "content": summary}, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        del saved

        resumed = Keybox.resume_replay(child_log, master)
        assert resumed.replay_identity == identity
        compressed = json.loads(child_log.read_text(encoding="utf-8"))["content"]
        assert compressed.encode() == summary.encode()
        resumed.validate_references(session, compressed)
        persisted = json.loads(transcript.read_text(encoding="utf-8"))["content"]
        assert persisted.encode() == projected.encode()
        assert resumed.redact_model_text(session, persisted) == persisted
        assert (
            resumed.restore_strict(session, persisted, len(original.encode()))
            == original
        )
        assert resumed.restore_strict(session, compressed, 4096) == (
            "Keep long-message-fixture; beneficiary: fixture@example.org"
        )
        assert "long-message-fixture" not in transcript.read_text(encoding="utf-8")
        assert "password=resumed-fixture" not in resumed.redact(
            session, "password=resumed-fixture"
        )


if __name__ == "__main__":
    main()
    test_chat_replay()
    test_long_compressed_resume()
