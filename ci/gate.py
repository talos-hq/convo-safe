"""Run the same validation lanes locally and in GitHub Actions."""

import argparse
import subprocess


def main():
    """Run one lane or the entire local gate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "lane", choices=("all", "lint", "unit", "smoke"), nargs="?", default="all"
    )
    lane = parser.parse_args().lane
    if lane in ("all", "lint"):
        subprocess.run(["python3", "ci/lint.py"], check=True)
    if lane in ("all", "unit"):
        subprocess.run(["soldr", "cargo", "test", "--locked"], check=True)
    if lane in ("all", "smoke"):
        subprocess.run(["python3", "ci/wheel.py", "smoke"], check=True)


if __name__ == "__main__":
    main()
