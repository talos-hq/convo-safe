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
MODEL = "fixture-model"


class FixtureProvider(BaseHTTPRequestHandler):
    """Capture every request body and return a synthetic assistant reply."""

    def _json(self, response):
        body = json.dumps(response).encode()
        self.send_response(200)
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
        "NO_PROXY": "127.0.0.1",
    }


def check_turn(env, captured):
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
        check=True,
    )
    assert INPUT_EMAIL not in answer.stdout and OUTPUT_EMAIL not in answer.stdout
    requests = [json.dumps(record) for record in captured if record.get("messages")]
    assert requests and any("[[CONVO_SAFE:" in request for request in requests)
    assert all(INPUT_EMAIL not in request for request in requests)


def main():
    """Run the fixture with a disposable Hermes profile and stop only its gateway."""
    with (
        TemporaryDirectory() as directory,
        ThreadingHTTPServer(("127.0.0.1", 0), FixtureProvider) as server,
    ):
        server.captured = []
        fixture = Thread(target=server.serve_forever, daemon=True)
        fixture.start()
        env = profile_environment(
            Path(directory), f"http://127.0.0.1:{server.server_port}/v1"
        )
        try:
            check_turn(env, server.captured)
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
