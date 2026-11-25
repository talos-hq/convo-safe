"""Exercise the package and native worker after installing the built wheel."""

import json
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
        redacted = box.redact(session, original)
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


if __name__ == "__main__":
    main()
