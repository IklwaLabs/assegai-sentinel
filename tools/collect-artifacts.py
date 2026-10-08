#!/usr/bin/env python3
"""Copies built bundles to the filenames site/release-manifest.json advertises.

Tauri names its own output after its internal template, so an NSIS installer comes out as
something like `Sentinel_0.1.0_x64_en-US-setup.exe` and a Debian package as
`sentinel_0.1.0_amd64.deb`. Those names carry the bundle target, the upstream version and the
locale. Publishing them means a download URL that changes when Tauri is upgraded, and a page
whose links have to be rewritten by hand after every release.

The manifest already declares stable, versioned names such as
`Sentinel-0.1.0-windows-x64-setup.exe`. This script makes the pipeline produce exactly those,
so the download page and the artifacts cannot disagree.

It fails loudly. A declared artifact with no matching build output is an error, not a silent
skip: a missing file discovered by a user is far worse than a failed release job.

    python tools/collect-artifacts.py --platform windows --staging artifacts
    python tools/collect-artifacts.py --platform linux  --staging artifacts --dry-run
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "site" / "release-manifest.json"

# Where each platform's bundler writes, and which declared artifact each built file satisfies.
#
# The left side is a glob relative to the repository root. The right side lists the declared
# asset names that this glob is expected to provide, in the order they appear in the manifest, so
# the mapping is positional and therefore easy to get wrong by accident -- which is why the
# same list is asserted against the manifest at startup below.
# Where each declared `kind` is built, as globs relative to the repository root.
#
# The kind names are specific -- `installer-nsis` and `installer-msi` rather than two
# `installer`s -- because each artifact needs its own source. A manifest that declares two
# artifacts with the same kind is rejected in verify_kind_map, so this table stays honest as
# the manifest gains platforms and artifacts.
SOURCE_GLOBS: dict[str, dict[str, list[str]]] = {
    "windows": {
        "installer-nsis": ["target/release/bundle/nsis/*.exe"],
        "installer-msi": ["target/release/bundle/msi/*.msi"],
        "cli": ["target/release/sentinel.exe"],
    },
    "linux": {
        "package-deb": ["target/release/bundle/debian/*.deb"],
        "package-appimage": ["target/release/bundle/appimage/*.AppImage"],
        "cli": ["target/release/sentinel"],
    },
    "macos": {
        "installer-dmg": ["target/release/bundle/dmg/*.dmg"],
        "cli": ["target/release/sentinel"],
    },
    "android": {
        "package-apk": ["apps/desktop/src-tauri/gen/android/**/*.apk"],
    },
}

# The one artifact assembled here rather than copied, because a GitHub release asset cannot be a
# directory. Declared in the manifest as the zipped application bundle.
ARCHIVE_KIND = "archive-app"


class CollectError(RuntimeError):
    pass


def load_manifest() -> dict:
    import json

    try:
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CollectError(f"no manifest at {MANIFEST_PATH}") from None
    except json.JSONDecodeError as error:
        raise CollectError(f"{MANIFEST_PATH} is not valid JSON: {error}") from None


def load_platform(platform_id: str) -> dict:
    manifest = load_manifest()
    for platform in manifest.get("platforms", []):
        if platform.get("id") == platform_id:
            return platform
    known = ", ".join(p.get("id", "?") for p in manifest.get("platforms", []))
    raise CollectError(f"no platform {platform_id!r} in the manifest. Known: {known}")


def verify_kind_map(platform: dict, platform_id: str) -> None:
    """Every declared artifact's `kind` must be one this platform knows how to build.

    Catches a manifest that adds a `.dmg` to Linux, or a new kind nobody has written a glob
    for, before the job spends twenty minutes compiling to fail at the copy step.
    """
    globs = SOURCE_GLOBS.get(platform_id, {})
    unknown = [
        artifact.get("label", "?")
        for artifact in platform.get("artifacts", [])
        if artifact.get("kind") not in globs and artifact.get("kind") != ARCHIVE_KIND
    ]
    if unknown:
        raise CollectError(
            f"{platform_id}: manifest declares artifact kind(s) with no source glob: "
            f"{', '.join(unknown)}. Add one to SOURCE_GLOBS in this script."
        )

    # Two artifacts sharing a kind would resolve to the same glob, so the second would silently
    # overwrite the first. The kinds exist to prevent exactly that.
    seen: dict[str, str] = {}
    for artifact in platform.get("artifacts", []):
        kind = artifact["kind"]
        label = artifact.get("label", artifact.get("asset", "?"))
        if kind in seen:
            raise CollectError(
                f"{platform_id}: {label!r} and {seen[kind]!r} both declare kind {kind!r}, so they "
                "would be collected from the same build output. Give them distinct kinds."
            )
        seen[kind] = label


def newest(paths: list[pathlib.Path]) -> pathlib.Path | None:
    """The most recently modified match.

    A bundle directory can contain more than one file when a previous build is still present,
    and picking the newest is the only choice that reliably matches what was just built.
    """
    if not paths:
        return None
    return max(paths, key=lambda p: p.stat().st_mtime)


def collect(platform_id: str, staging: pathlib.Path, dry_run: bool) -> list[tuple[str, str]]:
    platform = load_platform(platform_id)
    verify_kind_map(platform, platform_id)
    manifest_version = load_manifest()["release"]["version"]

    planned: list[tuple[str, str]] = []
    problems: list[str] = []

    for artifact in platform.get("artifacts", []):
        declared = artifact["asset"]
        kind = artifact["kind"]

        if kind == ARCHIVE_KIND:
            planned.append((ARCHIVE_KIND, declared))
            continue

        globs = SOURCE_GLOBS[platform_id][kind]

        matches: list[pathlib.Path] = []
        for pattern in globs:
            matches.extend(pathlib.Path(p) for p in REPO_ROOT.glob(pattern))
        matches = [m for m in matches if m.is_file()]

        if not matches:
            problems.append(
                f"  {declared}: nothing matched {', '.join(globs) or '(no glob configured)'}"
            )
            continue

        source = newest(matches)
        planned.append(("copy", f"{declared}<-{source.relative_to(REPO_ROOT)}"))

    if problems:
        raise CollectError(
            f"{platform_id}: {len(problems)} declared artifact(s) have no build output.\n"
            + "\n".join(problems)
            + f"\n  (manifest version {manifest_version}; was the bundle step run?)"
        )

    # Checked here rather than at copy time, so a dry run cannot plan an archive that would
    # fail an hour later in a real run.
    archives = [declared for action, declared in planned if action == ARCHIVE_KIND]
    if archives and shutil.which("ditto") is None:
        raise CollectError(
            f"{platform_id}: the manifest declares {', '.join(archives)}, which needs ditto to "
            "build. ditto is only available on macOS, so this platform's job must run there."
        )

    if dry_run:
        for action, detail in planned:
            print(f"would {action} {detail}")
        return planned

    staging.mkdir(parents=True, exist_ok=True)

    for action, detail in planned:
        if action == "copy":
            declared, source = detail.split("<-", 1)
            shutil.copy2(REPO_ROOT / source, staging / declared)
        elif action == ARCHIVE_KIND:
            archive_app_bundle(staging / detail)
        else:  # pragma: no cover - unreachable while collect() only emits the two above
            raise CollectError(f"unknown action {action!r}")

    return planned


def archive_app_bundle(destination: pathlib.Path) -> None:
    """Zip the .app directory, preserving the symlinks and permissions a bundle needs.

    A .app is a directory of Mach-O binaries and framework symlinks, so archiving the parent
    would sweep up everything else in the bundle directory, and a zip written file by file loses
    the executable bits that Gatekeeper checks. `ditto` is the tool macOS ships for exactly this
    and produces the archive Finder and Gatekeeper both understand.
    """
    app = REPO_ROOT / "target" / "release" / "bundle" / "macos" / "Sentinel.app"
    if not app.is_dir():
        raise CollectError(f"no application bundle at {app}")

    ditto = shutil.which("ditto")
    if ditto is None:
        # Reached when this script runs anywhere but macOS, which is easy to do by accident:
        # the macOS column of the manifest is readable from any platform, and `--dry-run`
        # would otherwise plan an archive it cannot build.
        raise CollectError(
            "ditto was not found. The macOS application bundle can only be archived on macOS, "
            "because ditto is part of the system and no cross-platform zip preserves the "
            "symlinks and permission bits a .app requires."
        )

    import subprocess

    result = subprocess.run(
        [ditto, "-c", "-k", "--keepParent", str(app), str(destination)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise CollectError(f"ditto failed: {result.stderr.strip() or result.stdout.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=sorted(SOURCE_GLOBS))
    parser.add_argument(
        "--staging",
        type=pathlib.Path,
        default=pathlib.Path("artifacts"),
        help="Directory the renamed artifacts are copied into.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be copied without touching the filesystem.",
    )
    args = parser.parse_args()

    try:
        planned = collect(args.platform, args.staging, args.dry_run)
    except CollectError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    verb = "would collect" if args.dry_run else "collected"
    print(f"{verb} {len(planned)} artifact(s) for {args.platform}")
    for action, detail in planned:
        print(f"  {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())