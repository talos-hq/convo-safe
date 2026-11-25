"""Check a protected CLI turn against a loopback-only OpenAI-compatible fixture."""

import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

INPUT_EMAIL = "input@example.org"
OUTPUT_EMAIL = "echo@example.org"
ERROR_EMAIL = "failure@example.org"
MODEL = "fixture-model"


class FixtureProvider(BaseHTTPRequestHandler):
    """Capture every request body and return a synthetic assistant reply."""

    def _json(self, response, status=200):
        body = json.dumps(response).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # pylint: disable=invalid-name
        """Advertise the fixture model."""
        self._json({"object": "list", "data": [{"id": MODEL, "object": "model"}]})

    def do_POST(self):  # pylint: disable=invalid-name
        """Store the submitted payload and return a complete reply."""
        self.server.captured.append(
            json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        )
        if self.server.fail_requests:
            self._json(
                {
                    "error": {
                        "message": f"Provider echoed {ERROR_EMAIL}",
                        "type": "invalid_request_error",
                    }
                },
                status=400,
            )
            return
        self._json(
            {
                "id": "chatcmpl-fixture",
                "object": "chat.completion",
                "created": 1,
                "model": MODEL,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": f"Reply to {OUTPUT_EMAIL}",
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                },
            }
        )

    def log_request(self, code="-", size="-"):
        """Keep the fixture log free of routine HTTP traces."""
        del code, size


def profile_environment(root, url):
    """Give each child just the isolated profile and synthetic credentials."""
    config = f"model:\n  default: {MODEL}\n  provider: custom\n  base_url: {url}\n"
    (root / "config.yaml").write_text(config, encoding="utf-8")
    inherited = {
        name: os.environ[name]
        for name in ("HOME", "PATH", "PYTHONPATH", "SYSTEMROOT")
        if name in os.environ
    }
    return {
        **inherited,
        "HERMES_HOME": str(root),
        "HERMES_RUNTIME_DIR": str(root / "runtime"),
        "HERMES_CONVO_SAFE_MASTER_KEY": bytes(32).hex(),
        "OPENAI_API_KEY": "fixture",
        "CUSTOM_API_KEY": "fixture",
        "HERMES_DUMP_REQUEST_STDOUT": "1",
        "NO_PROXY": "127.0.0.1",
    }


def check_turn(env, captured, *, expect_failure=False):
    """Resume a newly bound session through the ordinary one-shot CLI."""
    cli = [sys.executable, "-m", "hermes_cli.main"]
    created = subprocess.run(
        [*cli, "sessions", "create-protected"],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    session = created.stdout.strip().splitlines()[-1]
    answer = subprocess.run(
        [
            *cli,
            "chat",
            "--oneshot",
            "--resume",
            session,
            "-q",
            f"Write to {INPUT_EMAIL}",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert answer.returncode == int(expect_failure)
    output = answer.stdout + answer.stderr
    assert all(
        email not in output for email in (INPUT_EMAIL, OUTPUT_EMAIL, ERROR_EMAIL)
    )
    requests = [json.dumps(record) for record in captured if record.get("messages")]
    assert requests and any("[[CONVO_SAFE:" in request for request in requests)
    assert all(INPUT_EMAIL not in request for request in requests)


def check_failure_diagnostics(root):
    """Check the durable request dump and all text diagnostics after the failure."""
    dumps = list(root.rglob("request_dump_*.json"))
    assert dumps
    assert any(
        "[[CONVO_SAFE:"
        in json.loads(path.read_text(encoding="utf-8"))["error"]["message"]
        for path in dumps
    )
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".log", ".json", ".jsonl"}:
            contents = path.read_bytes()
            assert ERROR_EMAIL.encode() not in contents, path.relative_to(root)


def main():
    """Run the fixture with a disposable Hermes profile and stop only its gateway."""
    with (
        TemporaryDirectory() as directory,
        ThreadingHTTPServer(("127.0.0.1", 0), FixtureProvider) as server,
    ):
        server.captured = []
        server.fail_requests = False
        fixture = Thread(target=server.serve_forever, daemon=True)
        fixture.start()
        root = Path(directory)
        env = profile_environment(root, f"http://127.0.0.1:{server.server_port}/v1")
        try:
            check_turn(env, server.captured)
            server.captured.clear()
            server.fail_requests = True
            check_turn(env, server.captured, expect_failure=True)
            check_failure_diagnostics(root)
        finally:
            server.shutdown()
            fixture.join()
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from hermes_cli.gateway import stop_profile_gateway; stop_profile_gateway()",
                ],
                env=env,
                timeout=30,
                check=True,
            )
    print("Hermes CLI protected loopback passed")


if __name__ == "__main__":
    main()
