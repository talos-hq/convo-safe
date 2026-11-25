"""Run Rust and Python source checks."""

import subprocess


def main():
    """Check the Rust workspace and the Python source paths."""
    subprocess.run(["soldr", "cargo", "fmt", "--check"], check=True)
    subprocess.run(
        [
            "soldr",
            "cargo",
            "clippy",
            "--locked",
            "--all-targets",
            "--all-features",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--",
            "-D",
            "warnings",
        ],
        check=True,
    )
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--only-group",
            "lint",
            "--no-emit-project",
            "--output-file",
            "target/ci-lint-requirements.txt",
            "--quiet",
        ],
        check=True,
    )
    subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            "--with-requirements",
            "target/ci-lint-requirements.txt",
            "ruff",
            "check",
            "ci",
            "python",
            "tests/python_smoke.py",
            "tests/hermes_replay.py",
            "tests/hermes_runtime_replay.py",
        ],
        check=True,
    )
    subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            "--with-requirements",
            "target/ci-lint-requirements.txt",
            "ruff",
            "format",
            "--check",
            "ci",
            "python",
            "tests/python_smoke.py",
            "tests/hermes_replay.py",
            "tests/hermes_runtime_replay.py",
        ],
        check=True,
    )
    subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            "--with-requirements",
            "target/ci-lint-requirements.txt",
            "pylint",
            "ci",
            "python",
            "tests/python_smoke.py",
            "tests/hermes_replay.py",
            "tests/hermes_runtime_replay.py",
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
