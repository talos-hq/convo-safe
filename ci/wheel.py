"""Build and test the installed Convo Safe wheel."""

import argparse
import os
import re
import subprocess
import tempfile
import tomllib
import zipfile
from pathlib import Path

TARGET = "x86_64-unknown-linux-gnu"


def check_wheel(wheel, release):
    """Verify both native files and the release libc floor."""
    if "-cp310-abi3-" not in wheel.name:
        raise ValueError(f"unexpected wheel ABI: {wheel.name}")
    if release and "manylinux_2_17_x86_64" not in wheel.name:
        raise ValueError(f"unexpected release wheel platform: {wheel.name}")
    with zipfile.ZipFile(wheel) as archive, tempfile.TemporaryDirectory() as directory:
        for pattern in (
            r"[^/]+\.data/scripts/convo-safe",
            r"convo_safe/_native\.abi3\.so",
        ):
            (member,) = [
                name for name in archive.namelist() if re.fullmatch(pattern, name)
            ]
            data = archive.read(member)
            if not data.startswith(b"\x7fELF"):
                raise ValueError(f"expected an ELF binary: {member}")
            if release:
                binary = Path(directory, Path(member).name)
                binary.write_bytes(data)
                versions = subprocess.check_output(
                    ["readelf", "--version-info", binary], text=True
                )
                for major, minor in re.findall(r"GLIBC_(\d+)\.(\d+)", versions):
                    if (int(major), int(minor)) > (2, 17):
                        raise ValueError(f"{member} requires glibc {major}.{minor}")


def check_release(out):
    """Check release inputs before building artifacts."""
    version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]["version"]
    crate_version = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))[
        "package"
    ]["version"]
    tag = os.environ.get("GITHUB_REF_NAME")
    if version != crate_version or (
        os.environ.get("GITHUB_REF_TYPE") == "tag" and tag != f"v{version}"
    ):
        raise ValueError("release tag and manifest versions must agree")
    if out.exists() and any(out.iterdir()):
        raise ValueError("release artifact directory must be empty")


def build(out, release):
    """Build the wheel and smoke-test each selected Python version."""
    if release:
        check_release(out)
    config = ["--release"] if release else []
    subprocess.run(
        ["soldr", "wheel", *config, "--target", TARGET, "--", "--locked", "--out", out],
        check=True,
    )
    (wheel,) = out.glob("*.whl")
    check_wheel(wheel, release)
    for python in ("3.10", "3.14") if release else ("3.10",):
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--isolated",
                "--python",
                python,
                "--with",
                wheel.resolve(),
                "python",
                "tests/python_smoke.py",
            ],
            check=True,
        )
    if release:
        subprocess.run(["uv", "build", "--sdist", "--out-dir", out], check=True)
        (sdist,) = out.glob("*.tar.gz")
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--isolated",
                "--python",
                "3.10",
                "--with",
                sdist.resolve(),
                "python",
                "tests/python_smoke.py",
            ],
            check=True,
        )

        subprocess.run(
            ["uv", "tool", "run", "twine", "check", "--strict", wheel, sdist],
            check=True,
        )


def main():
    """Run quick wheel smoke or stage the release artifacts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("smoke", "release"))
    parser.add_argument("--out", type=Path, default=Path("dist/release"))
    args = parser.parse_args()
    if args.mode == "release":
        build(args.out, release=True)
    else:
        with tempfile.TemporaryDirectory() as directory:
            build(Path(directory), release=False)


if __name__ == "__main__":
    main()
