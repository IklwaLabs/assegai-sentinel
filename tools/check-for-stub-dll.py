#!/usr/bin/env python3
"""Fails the build if the CI stub wpcap.dll has leaked into a release bundle.

The stub stands in for a machine with no capture driver so a Windows test binary can start.
It is built by tools/build-stub-wpcap-dll.ps1 and put on PATH for exactly one step, the one
that runs `cargo test`. It is never supposed to be anywhere near a shipped artifact.

It would be easy to get wrong: add the stub directory to PATH at the job level instead of the
step level, and every binary built afterwards -- including the one in the installer -- resolves
a DLL whose exports abort the process. The result would ship an application that installs
cleanly, reports interfaces as available, and then dies on the first capture.

That failure is invisible in CI and obvious to a user, so it is checked here rather than left
to care. Detection is by PE content, not by file name: the stub's exports all resolve to one
function called pcap_stub_trap, and no genuine Npcap build contains that symbol.

    python tools/check-for-stub-dll.py staging/
    python tools/check-for-stub-dll.py --quiet target/release/bundle/
"""

from __future__ import annotations

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The single function every stub export aliases. If this string appears in a DLL's export
# table, that DLL is the stub and has no business in a release.
TRAP_SYMBOL = b"pcap_stub_trap"

# Also refuse the trap's message, which survives in the binary even where the export name was
# stripped or renamed.
TRAP_MESSAGE = b"a test called into the CI stub wpcap.dll"

# Extensions worth opening. A binary that is not one of these cannot be a DLL.
BINARY_SUFFIXES = {".dll", ".exe", ".msi", ".appimage", ".deb", ".zip", ".apk", ".msixbundle"}


class CheckError(RuntimeError):
    pass


def looks_like_stub(path: pathlib.Path) -> str | None:
    """Returns the marker found in `path`, or None when it is not the stub."""
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CheckError(f"cannot read {path}: {error}") from error

    if TRAP_SYMBOL in data:
        return TRAP_SYMBOL.decode()
    if TRAP_MESSAGE in data:
        return TRAP_MESSAGE.decode()
    return None


def scan(roots: list[pathlib.Path]) -> list[tuple[pathlib.Path, str]]:
    """Walks each root looking for the stub."""
    findings: list[tuple[pathlib.Path, str]] = []
    for root in roots:
        if not root.exists():
            raise CheckError(f"{root} does not exist")
        candidates = [root] if root.is_file() else sorted(root.rglob("*"))
        for candidate in candidates:
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() not in BINARY_SUFFIXES:
                continue
            marker = looks_like_stub(candidate)
            if marker:
                findings.append((candidate, marker))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "roots",
        nargs="+",
        type=pathlib.Path,
        help="Files or directories to scan. Directories are searched recursively.",
    )
    parser.add_argument("--quiet", action="store_true", help="Only report failures.")
    args = parser.parse_args()

    try:
        findings = scan(args.roots)
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if findings:
        print(
            "The CI stub wpcap.dll has reached a release artifact.\n\n"
            "A shipped binary must resolve the real Npcap driver, or fail to start. This one\n"
            "resolves a stub whose every export terminates the process, so the application\n"
            "would install cleanly and then die on the first capture.\n\n"
            "Almost always this means the stub directory was added to PATH for the whole job\n"
            "instead of for the step that runs the tests.\n",
            file=sys.stderr,
        )
        for path, marker in findings:
            print(f"  {path}  ({marker})", file=sys.stderr)
        return 1

    if not args.quiet:
        scanned = sum(
            1
            for root in args.roots
            for candidate in ([root] if root.is_file() else root.rglob("*"))
            if candidate.is_file() and candidate.suffix.lower() in BINARY_SUFFIXES
        )
        print(f"No stub wpcap.dll among {scanned} binary file(s) in {len(args.roots)} path(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())