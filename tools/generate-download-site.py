#!/usr/bin/env python3
"""Generates the Sentinel download page from the release manifest.

The page is generated rather than hand-written for the same reason the product reference
PDF is: a download page that disagrees with what the pipeline actually publishes is a
support burden, and nobody notices until a user's download 404s.

Everything the page shows comes from one of two places:

  site/release-manifest.json   facts about the product and its platforms, written by hand
  the repository itself         version, product name, identifiers, and which commands exist

Nothing about a download link, a version number or a platform list is hardcoded here. If
the manifest says an artifact does not exist yet, the page says so in plain language
instead of rendering a button that fails.

Facts are cross-checked against the repository rather than trusted. A manifest claiming
version 0.2.0 while Cargo.toml says 0.1.0 is a stale manifest, and the generator fails
loudly rather than publishing a page offering a build that was never made.

Usage:
    python tools/generate-download-site.py                  # writes site/index.html
    python tools/generate-download-site.py --check          # fails if it would change
    python tools/generate-download-site.py --out path.html

Output is a single self-contained HTML file: no build step, no CDN, no runtime
JavaScript beyond a few lines for the platform tabs. It has to work on a file:// URL,
from a plain static host, and inside a web view that blocks third-party requests.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "site" / "release-manifest.json"
DEFAULT_OUTPUT = REPO_ROOT / "site" / "index.html"

# Extensions that are download links, grouped so each platform's buttons can be styled by
# kind. Kept here rather than in the manifest because it is presentation, not product data.
EXTENSION_LABELS = {
    ".exe": "Windows executable",
    ".msi": "Windows installer package",
    ".deb": "Debian package",
    ".AppImage": "AppImage",
    ".dmg": "macOS disk image",
    ".zip": "Archive",
    ".apk": "Android package",
}

# Which platform each file extension belongs to. The manifest lists artifacts under a
# platform, and this is only used to build the "other downloads" summary table, where the
# asset list is flat.
PLATFORM_FOR_EXTENSION = [
    (".msi", "windows"),
    (".exe", "windows"),
    (".deb", "linux"),
    (".AppImage", "linux"),
    (".dmg", "macos"),
    (".apk", "android"),
]


class ManifestError(RuntimeError):
    """The manifest disagrees with the repository.

    Raised instead of publishing, because every version of this that publishes anyway
    produces a page that is confidently wrong.
    """


def read_manifest(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ManifestError(f"no manifest at {path}") from None
    except json.JSONDecodeError as error:
        raise ManifestError(f"{path} is not valid JSON: {error}") from None


def workspace_version() -> str:
    """The version every crate in the workspace shares."""
    cargo = REPO_ROOT / "Cargo.toml"
    match = re.search(
        r"^\[workspace\.package\]\s*$(?P<body>.*?)(?=^\[|\Z)",
        cargo.read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise ManifestError(f"no [workspace.package] table in {cargo}")
    version = re.search(r'^version\s*=\s*"([^"]+)"', match.group("body"), re.MULTILINE)
    if not version:
        raise ManifestError(f"no workspace version in {cargo}")
    return version.group(1)


def tauri_identity() -> dict:
    """Product name and bundle identifier, which are the desktop app's real identity."""
    config = json.loads(
        (REPO_ROOT / "apps" / "desktop" / "src-tauri" / "tauri.conf.json").read_text(
            encoding="utf-8"
        )
    )
    return {
        "product_name": config.get("productName", "Sentinel"),
        "identifier": config.get("identifier", ""),
        "bundle_targets": config.get("bundle", {}).get("targets", []),
    }


def cli_subcommands() -> list[str]:
    """Subcommands the CLI actually declares, so the page cannot advertise a missing one."""
    source = (REPO_ROOT / "apps" / "cli" / "src" / "main.rs").read_text(encoding="utf-8")
    body = re.search(r"enum Command\s*\{(?P<body>.*?)\n\}", source, re.DOTALL)
    if not body:
        return []
    names = re.findall(r"^\s{4}([A-Z][A-Za-z]+)", body.group("body"), re.MULTILINE)
    return [name.lower() for name in names]


def verify_against_repository(manifest: dict) -> dict:
    """Cross-check every machine-readable fact the manifest asserts.

    Returns the resolved version and product identity. Raises ManifestError on a mismatch,
    because the alternative is a download page for a build that does not exist.
    """
    version = workspace_version()
    release = manifest.get("release", {})
    product = manifest.get("product", {})

    declared = release.get("version")
    if declared != version:
        raise ManifestError(
            f"manifest says version {declared!r} but Cargo.toml says {version!r}. "
            "Bump site/release-manifest.json or revert the code change."
        )

    expected_tag = release.get("tag")
    if expected_tag != f"v{version}":
        raise ManifestError(
            f"manifest tag {expected_tag!r} does not match version {version!r}; expected 'v{version}'."
        )

    cli_commands = cli_subcommands()
    for entry in manifest.get("cli_commands", []):
        name = entry.get("command", "").split()[1:2]
        if not name:
            continue
        subcommand = name[0]
        if cli_commands and subcommand not in cli_commands:
            raise ManifestError(
                f"manifest documents 'sentinel {subcommand}' but the CLI declares "
                f"{cli_commands}. Update the manifest or the CLI."
            )

    identity = tauri_identity()
    declared_name = product.get("name")
    if declared_name and declared_name != identity["product_name"]:
        raise ManifestError(
            f"manifest product name {declared_name!r} differs from tauri.conf.json "
            f"{identity['product_name']!r}."
        )

    for platform in manifest.get("platforms", []):
        for artifact in platform.get("artifacts", []):
            asset = artifact.get("asset", "")
            # The CLI is published as a bare executable on Linux and macOS, so an extension
            # is optional. What is not optional is a recognisable artifact kind.
            known = (".exe", ".msi", ".deb", ".AppImage", ".dmg", ".zip", ".apk")
            if not asset or "/" in asset or "\\" in asset:
                raise ManifestError(f"{asset!r} is not a plain file name.")
            if not asset.endswith(known):
                # A bare name is the CLI executable, which ships without an extension on the
                # two platforms where a binary does not need one.
                bare = pathlib.Path(asset).name == asset
                if bare:
                    if "cli" not in asset:
                        raise ManifestError(
                            f"{platform['id']}/{artifact.get('label', '?')}: {asset!r} has no "
                            f"extension and is not named as a CLI binary. Expected one of "
                            f"{', '.join(known)}."
                        )
                else:
                    raise ManifestError(
                        f"{platform['id']}/{artifact.get('label', '?')}: {asset!r} has an "
                        f"unrecognised extension. Expected one of {', '.join(known)}, or none "
                        "at all for the bare CLI executable."
                    )
            if version not in asset:
                raise ManifestError(
                    f"{asset!r} does not contain the version {version}. Stable artifact names "
                    "must be versioned so a published URL keeps resolving."
                )

    return {
        "version": version,
        "tag": expected_tag,
        "product_name": identity["product_name"],
        "identifier": identity["identifier"],
        "bundle_targets": identity["bundle_targets"],
        "cli_commands": cli_commands,
    }


def release_base_url(manifest: dict) -> str:
    """Where artifacts will be served from, once a release is published."""
    repo = manifest["product"]["repository"].rstrip("/")
    return f"{repo}/releases/download/{manifest['release']['tag']}"


def format_size(asset_name: str) -> str:
    """No fabricated sizes: an estimate here would be a lie in a download button's tooltip."""
    return EXTENSION_LABELS.get(pathlib.Path(asset_name).suffix.lower(), "Download")


def esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def render_platform_nav(manifest: dict, current: str | None) -> str:
    """Platform tabs.

    Rendered as links rather than a JS widget so the page works without script, and so the
    download page is crawlable and printable. Every tab is a real URL.
    """
    items = []
    for platform in manifest["platforms"]:
        slug = platform["id"]
        is_current = slug == current
        label = esc(platform["name"])
        status = platform.get("status")
        badge = ""
        if status == "partial":
            badge = '<span class="tab-badge">Analysis only</span>'
        href = f"#{slug}" if current else f"#platform-{slug}"
        attrs = ' aria-current="true"' if is_current else ""
        items.append(
            f'<a class="tab{" is-active" if is_current else ""}" href="{href}"{attrs}>'
            f"{label}{badge}</a>"
        )
    return '<nav class="tabs" aria-label="Platforms">' + "".join(items) + "</nav>"


def render_status_pill(status: str) -> str:
    if status == "supported":
        return '<span class="pill pill-ok">Supported</span>'
    if status == "partial":
        return '<span class="pill pill-warn">Analysis only</span>'
    return f'<span class="pill pill-muted">{esc(status)}</span>'


def render_download_list(manifest: dict, platform: dict, base_url: str) -> str:
    """Buttons for one platform.

    When the release is unpublished the buttons become non-interactive and the reason is
    shown. A download button that 404s tells the user the product is broken; a clear
    statement that the build has not shipped yet tells them the truth.
    """
    published = manifest["release"].get("published", False)
    rows = []
    for artifact in platform.get("artifacts", []):
        asset = esc(artifact["asset"])
        label = esc(artifact["label"])
        detail = esc(artifact.get("detail", ""))
        kind = esc(artifact.get("kind", "file"))
        if published:
            href = f"{base_url}/{asset}"
            action = (
                f'<a class="btn btn-primary" href="{href}" download>'
                f'<span class="btn-label">Download</span>'
                f'<span class="btn-file">{asset}</span></a>'
            )
        else:
            action = (
                f'<span class="btn btn-disabled" aria-disabled="true">'
                f'<span class="btn-label">Not yet published</span>'
                f'<span class="btn-file">{asset}</span></span>'
            )
        rows.append(
            f'<li class="artifact artifact-{kind}">'
            f"{action}"
            f'<p class="artifact-detail">{label}. {detail}</p>'
            "</li>"
        )
    return f'<ul class="artifacts">{"".join(rows)}</ul>'


def render_platform_section(manifest: dict, platform: dict, base_url: str) -> str:
    ident = esc(platform["id"])
    steps = "".join(f"<li><code>{esc(step)}</code></li>" for step in platform.get("install", []))
    driver = platform.get("driver", "")
    driver_link = ""
    if platform.get("driver_url"):
        driver_link = (
            f' <a href="{esc(platform["driver_url"])}" rel="noopener nofollow">{esc(driver)}</a>'
        )
    else:
        driver_link = f" {esc(driver)}"
    return f"""
    <section class="platform" id="platform-{ident}">
      <header class="platform-head">
        <h3>{esc(platform['name'])} {render_status_pill(platform.get('status', 'unknown'))}</h3>
        <p class="platform-summary">{esc(platform['summary'])}</p>
      </header>
      <div class="platform-grid">
        <div class="platform-downloads">
          <h4>Downloads</h4>
          {render_download_list(manifest, platform, base_url)}
        </div>
        <div class="platform-requirements">
          <h4>Requirements</h4>
          <dl>
            <dt>Capture driver</dt>
            <dd>{driver_link}</dd>
            <dt>Privileges</dt>
            <dd>{esc(platform.get('privilege', 'None'))}</dd>
          </dl>
          <h4>Installing</h4>
          <ol class="steps">{steps}</ol>
        </div>
      </div>
    </section>"""


def render_release_notice(manifest: dict) -> str:
    release = manifest["release"]
    if release.get("published"):
        return f"""
    <div class="notice notice-ok">
      <strong>{esc(release['tag'])} is published.</strong>
      Every artifact below is built on its own runner and verified on that platform before
      the release is cut.
    </div>"""
    reason = esc(release.get("unpublished_reason", ""))
    releases_url = esc(release.get("releases_url", ""))
    return f"""
    <div class="notice notice-warn">
      <strong>No published download yet.</strong>
      {reason}
      {'Artifacts appear on the <a href="' + releases_url + '" rel="noopener">releases page</a> once they are cut.' if releases_url else ''}
    </div>"""


def render_features(manifest: dict) -> str:
    items = "".join(
        f'<li class="feature"><h4>{esc(f["title"])}</h4><p>{esc(f["body"])}</p></li>'
        for f in manifest.get("features", [])
    )
    return f'<div class="feature-grid">{items}</div>'


def render_not_implemented(manifest: dict) -> str:
    items = "".join(
        f'<li><strong>{esc(item["title"])}.</strong> {esc(item["body"])}</li>'
        for item in manifest.get("not_implemented", [])
    )
    return f"""
    <section class="section" id="not-implemented">
      <h2>Not in this release</h2>
      <p class="section-lede">
        These are absent from the interface rather than faked. A threat rule that cannot fire,
        or a device list inferred from nothing, would be worse than an honest gap.
      </p>
      <ul class="gap-list">{items}</ul>
    </section>"""


def render_cli(manifest: dict) -> str:
    rows = "".join(
        f"<tr><td><code>{esc(entry['command'])}</code></td><td>{esc(entry['purpose'])}</td></tr>"
        for entry in manifest.get("cli_commands", [])
    )
    return f"""
    <section class="section" id="cli">
      <h2>Command line</h2>
      <p class="section-lede">
        The CLI is a thin client over the same engine as the desktop application, so the two
        cannot disagree about what your network is doing.
      </p>
      <table class="cli-table">
        <thead><tr><th>Command</th><th>Purpose</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p class="section-note">Add <code>--json</code> for machine-readable output, <code>-v</code>
      for more detail, <code>-q</code> for less.</p>
    </section>"""


def render_build_from_source(manifest: dict) -> str:
    source = manifest.get("build_from_source", {})
    commands = "".join(f"<li><code>{esc(c)}</code></li>" for c in source.get("commands", []))
    notes = "".join(f"<li>{esc(n)}</li>" for n in source.get("notes", []))
    return f"""
    <section class="section" id="build">
      <h2>Build from source</h2>
      <p class="section-lede">{esc(source.get('prerequisites', ''))}</p>
      <ol class="code-block">{commands}</ol>
      <ul class="note-list">{notes}</ul>
    </section>"""


def render_verification(manifest: dict) -> str:
    verification = manifest.get("verification", {})
    notes = "".join(f"<li>{esc(n)}</li>" for n in verification.get("notes", []))
    return f"""
    <section class="section" id="verify">
      <h2>Verify a download</h2>
      <p class="section-lede">{esc(verification.get('body', ''))}</p>
      <pre class="code-block"><code>{esc(verification.get('command', ''))}</code></pre>
      <ul class="note-list">{notes}</ul>
    </section>"""


def render_faq(manifest: dict) -> str:
    items = "".join(
        f'<details class="faq-item"><summary>{esc(item["q"])}</summary>'
        f'<p>{esc(item["a"])}</p></details>'
        for item in manifest.get("faq", [])
    )
    return f"""
    <section class="section" id="faq">
      <h2>Questions</h2>
      <div class="faq">{items}</div>
    </section>"""


def render_footer(manifest: dict) -> str:
    footer = manifest.get("footer", {})
    links = "".join(
        f'<a href="{esc(link["url"])}" rel="noopener">{esc(link["label"])}</a>'
        for link in footer.get("links", [])
    )
    product = manifest["product"]
    return f"""
    <footer class="site-footer">
      <div>
        <p class="footer-brand">{esc(product.get('vendor', ''))} &middot; {esc(product['name'])} {esc(manifest['release']['version'])}</p>
        <p class="footer-license">{esc(product.get('license', ''))} licensed.</p>
      </div>
      <nav class="footer-links" aria-label="Documentation">{links}</nav>
    </footer>"""


CSS = """
/*
 * Styling for the download page.
 *
 * Deliberately the same palette as the application, so the page and the product read as one
 * thing. Severity colours are not used at all: nothing on this page is an alert, and using
 * red for "not published" would be crying wolf.
 *
 * No web fonts, no CDN, no build step. The page has to render correctly with no network
 * access beyond its own host, in a web view that blocks third parties, and when printed.
 */
:root {
  --surface-base: #0b0d10;
  --surface-raised: #111419;
  --surface-overlay: #161a20;
  --surface-input: #1b2027;

  --border-subtle: #1e232b;
  --border-default: #242a33;
  --border-strong: #333b47;

  --text-primary: #f3f4f6;
  --text-secondary: #9ca3af;
  --text-muted: #6b7280;
  --text-faint: #4b5563;

  --accent: #f97316;
  --accent-hover: #fb8b3c;
  --accent-muted: #7c3a10;
  --accent-contrast: #1a0d03;

  --severity-medium: #f5b53d;
  --severity-safe: #3f9d6b;

  --font-sans: 'Inter', 'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', 'SF Mono', 'Cascadia Code', ui-monospace, monospace;

  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-5: 1.5rem;
  --space-6: 2rem;
  --space-7: 3rem;

  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;

  --measure: 68ch;
}

@media (prefers-color-scheme: light) {
  :root {
    --surface-base: #ffffff;
    --surface-raised: #f7f8fa;
    --surface-overlay: #ffffff;
    --surface-input: #eef0f4;
    --border-subtle: #e6e8ec;
    --border-default: #d8dce2;
    --border-strong: #b9c0c9;
    --text-primary: #11151b;
    --text-secondary: #4a5462;
    --text-muted: #6b7583;
    --text-faint: #97a0ad;
    --accent-muted: #fed7c4;
    --accent-contrast: #ffffff;
  }
}

*, *::before, *::after { box-sizing: border-box; }

html { -webkit-text-size-adjust: 100%; }

body {
  margin: 0;
  background: var(--surface-base);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 16px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

.wrap {
  max-width: 68rem;
  margin: 0 auto;
  padding: 0 var(--space-5);
}

a { color: var(--accent); }
a:hover { color: var(--accent-hover); }

code, pre { font-family: var(--font-mono); font-size: 0.875em; }

code {
  background: var(--surface-input);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  padding: 0.1em 0.35em;
  color: var(--text-primary);
  overflow-wrap: anywhere;
}

pre.code-block {
  background: var(--surface-raised);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  overflow-x: auto;
}
pre.code-block code { background: none; border: none; padding: 0; }

:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}

/* ---------------------------------------------------------------- masthead */

.masthead {
  border-bottom: 1px solid var(--border-subtle);
  padding: var(--space-4) 0;
  position: sticky;
  top: 0;
  background: var(--surface-base);
  z-index: 10;
}
.masthead .wrap {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  flex-wrap: wrap;
}
.brand {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  font-weight: 600;
  color: var(--text-primary);
  text-decoration: none;
}
.brand-mark {
  width: 28px;
  height: 28px;
  border-radius: var(--radius-md);
  background: linear-gradient(140deg, var(--accent) 0%, #dc2626 100%);
  flex: none;
}
.brand-sub {
  color: var(--text-muted);
  font-weight: 400;
  font-size: 0.875rem;
}
.version-tag {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--text-secondary);
  background: var(--surface-raised);
  border: 1px solid var(--border-default);
  border-radius: 999px;
  padding: 0.15rem 0.6rem;
}

/* ------------------------------------------------------------------- hero */

.hero { padding: var(--space-7) 0 var(--space-6); }
.hero h1 {
  font-size: clamp(2rem, 5vw, 3rem);
  line-height: 1.15;
  margin: 0 0 var(--space-4);
  letter-spacing: -0.02em;
}
.hero-lede {
  font-size: 1.125rem;
  color: var(--text-secondary);
  max-width: var(--measure);
  margin: 0 0 var(--space-5);
}
.pipeline {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  align-items: center;
  font-family: var(--font-mono);
  font-size: 0.8125rem;
  color: var(--text-muted);
  margin-bottom: var(--space-5);
}
.pipeline-step {
  background: var(--surface-raised);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  padding: 0.2rem 0.55rem;
}
.pipeline-arrow { color: var(--text-faint); }
.pipeline-meta { color: var(--text-faint); margin-left: var(--space-2); }

.hero-actions { display: flex; gap: var(--space-3); flex-wrap: wrap; }

.btn {
  display: inline-flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.1rem;
  text-decoration: none;
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--border-default);
  background: var(--surface-raised);
  color: var(--text-primary);
  font-weight: 500;
  transition: background 120ms ease, border-color 120ms ease;
}
.btn-label { font-size: 0.9375rem; }
.btn-file {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--text-muted);
  overflow-wrap: anywhere;
}
.btn-primary {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--accent-contrast);
}
.btn-primary .btn-file { color: var(--accent-contrast); opacity: 0.75; }
.btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); color: var(--accent-contrast); }
.btn-ghost:hover { background: var(--surface-overlay); border-color: var(--border-strong); }
.btn:visited, .btn:link { color: var(--text-primary); }
.btn-primary:visited, .btn-primary:link { color: var(--accent-contrast); }

/*
 * A disabled download still has to be legible. Removing it entirely would leave the page
 * looking empty and unexplained; dimming it and saying why is honest.
 */
.btn-disabled {
  background: var(--surface-raised);
  border-color: var(--border-subtle);
  border-style: dashed;
  color: var(--text-muted);
  cursor: not-allowed;
}
.btn-disabled .btn-file { color: var(--text-faint); }

/* ---------------------------------------------------------------- notices */

.notice {
  border: 1px solid var(--border-default);
  border-left: 3px solid var(--border-strong);
  border-radius: var(--radius-md);
  background: var(--surface-raised);
  padding: var(--space-4);
  margin: 0 0 var(--space-6);
  max-width: var(--measure);
  color: var(--text-secondary);
}
.notice strong { color: var(--text-primary); }
.notice-warn { border-left-color: var(--severity-medium); }
.notice-ok { border-left-color: var(--severity-safe); }

/* ------------------------------------------------------------------- tabs */

.tabs {
  display: flex;
  gap: var(--space-1);
  border-bottom: 1px solid var(--border-subtle);
  margin-bottom: var(--space-6);
  overflow-x: auto;
}
.tab {
  padding: var(--space-3) var(--space-4);
  color: var(--text-secondary);
  text-decoration: none;
  border-bottom: 2px solid transparent;
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
}
.tab:hover { color: var(--text-primary); }
.tab.is-active { color: var(--text-primary); border-bottom-color: var(--accent); }
.tab-badge {
  font-size: 0.6875rem;
  font-family: var(--font-mono);
  color: var(--severity-medium);
  border: 1px solid currentColor;
  border-radius: 999px;
  padding: 0 0.4rem;
}

/* -------------------------------------------------------------- platforms */

.platform {
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background: var(--surface-raised);
  padding: var(--space-5);
  margin-bottom: var(--space-5);
  scroll-margin-top: 5rem;
}
.platform-head { margin-bottom: var(--space-4); }
.platform-head h3 {
  margin: 0 0 var(--space-2);
  font-size: 1.375rem;
  display: flex;
  align-items: center;
  gap: var(--space-3);
  flex-wrap: wrap;
}
.platform-summary { margin: 0; color: var(--text-secondary); max-width: var(--measure); }

.pill {
  font-size: 0.75rem;
  font-weight: 500;
  border-radius: 999px;
  padding: 0.1rem 0.6rem;
  border: 1px solid currentColor;
}
.pill-ok { color: var(--severity-safe); }
.pill-warn { color: var(--severity-medium); }
.pill-muted { color: var(--text-muted); }

.platform-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: var(--space-6);
}
@media (max-width: 46rem) {
  .platform-grid { grid-template-columns: minmax(0, 1fr); gap: var(--space-5); }
}

.platform h4, .section h2 { margin: 0 0 var(--space-3); font-size: 1rem; }
.platform-requirements h4 + dl,
.platform-requirements dl + h4 { margin-top: var(--space-5); }

.artifacts { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--space-3); }
.artifact .btn { width: 100%; }
.artifact-detail {
  margin: var(--space-1) 0 0;
  font-size: 0.8125rem;
  color: var(--text-muted);
}

dl { margin: 0; }
dt { font-weight: 500; color: var(--text-primary); font-size: 0.875rem; }
dd { margin: var(--space-1) 0 var(--space-3); color: var(--text-secondary); font-size: 0.875rem; }

.steps, .note-list, .gap-list { margin: 0; padding-left: 1.15rem; color: var(--text-secondary); }
.steps li, .note-list li, .gap-list li { margin-bottom: var(--space-2); }
.note-list { font-size: 0.875rem; color: var(--text-muted); }

/* --------------------------------------------------------------- sections */

.section { padding: var(--space-6) 0; border-top: 1px solid var(--border-subtle); scroll-margin-top: 5rem; }
.section h2 { font-size: 1.5rem; }
.section-lede { color: var(--text-secondary); max-width: var(--measure); margin: 0 0 var(--space-4); }
.section-note { color: var(--text-muted); font-size: 0.875rem; }

.feature-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
  gap: var(--space-4);
}
.feature {
  border: 1px solid var(--border-subtle);
  border-left: 2px solid var(--accent-muted);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  background: var(--surface-raised);
}
.feature h4 { margin: 0 0 var(--space-2); font-size: 0.9375rem; }
.feature p { margin: 0; color: var(--text-secondary); font-size: 0.875rem; }

.cli-table { width: 100%; border-collapse: collapse; font-size: 0.9375rem; }
.cli-table th, .cli-table td {
  text-align: left;
  padding: var(--space-2) var(--space-3);
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: top;
}
.cli-table th { color: var(--text-muted); font-weight: 500; font-size: 0.8125rem; text-transform: uppercase; letter-spacing: 0.04em; }
.cli-table td:last-child { color: var(--text-secondary); }

.faq-item {
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  margin-bottom: var(--space-2);
  background: var(--surface-raised);
}
.faq-item summary {
  cursor: pointer;
  font-weight: 500;
  color: var(--text-primary);
  list-style-position: outside;
}
.faq-item summary::marker { color: var(--accent); }
.faq-item p { margin: var(--space-3) 0 0; color: var(--text-secondary); max-width: var(--measure); }

/* ----------------------------------------------------------------- footer */

.site-footer {
  border-top: 1px solid var(--border-subtle);
  padding: var(--space-6) 0;
  margin-top: var(--space-6);
  display: flex;
  justify-content: space-between;
  gap: var(--space-4);
  flex-wrap: wrap;
}
.footer-brand { margin: 0; font-weight: 600; }
.footer-license { margin: var(--space-1) 0 0; color: var(--text-muted); font-size: 0.875rem; }
.footer-links { display: flex; gap: var(--space-4); flex-wrap: wrap; align-items: flex-start; }
.footer-links a { font-size: 0.875rem; color: var(--text-secondary); }

.visually-hidden {
  position: absolute;
  width: 1px; height: 1px;
  padding: 0; margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}

/* ------------------------------------------------------------------ print */

@media print {
  :root {
    --surface-base: #ffffff;
    --surface-raised: #ffffff;
    --surface-overlay: #ffffff;
    --surface-input: #f2f2f2;
    --text-primary: #000000;
    --text-secondary: #333333;
    --text-muted: #555555;
    --text-faint: #777777;
    --border-subtle: #cccccc;
    --border-default: #999999;
  }
  body { background: #fff; }
  .masthead { position: static; }
  .btn-disabled { border-style: solid; }
  .tabs { display: none; }
  .platform, .feature, .faq-item { break-inside: avoid; }
  .faq-item[open] p, .faq-item p { display: block; }
  a[href^="http"]::after { content: " (" attr(href) ")"; font-size: 0.75em; color: #555555; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
"""


def verify_internal_anchors(rendered: str) -> None:
    """Every `href="#..."` must resolve to an `id` in the same document.

    A dead in-page link on a download page is the same failure as a dead download button:
    the visitor finds out something is broken only after deciding to use the product. This is
    checked at generation time because it is cheap here and invisible in review.
    """
    ids = set(re.findall(r'\bid="([^"]+)"', rendered))
    # The capture group starts after the '#', so the targets are bare ids.
    targets = set(re.findall(r'href="#([^"]+)"', rendered))
    broken = sorted(targets - ids)
    if broken:
        raise ManifestError(
            f"page links to anchor(s) that do not exist: {', '.join('#' + b for b in broken)}"
        )


def build_html(manifest: dict, facts: dict) -> str:
    """Assemble the page.

    `facts` comes from verify_against_repository, so the version printed here is the version
    in Cargo.toml rather than whatever the manifest happened to say.
    """
    product = manifest["product"]
    base_url = release_base_url(manifest)

    platforms_html = "".join(
        render_platform_section(manifest, platform, base_url)
        for platform in manifest["platforms"]
    )
    pipeline = "".join(
        f'<span class="pipeline-step">{esc(step)}</span>'
        for step in ["capture", "decode", "flow engine", "detection", "SQLite", "interface"]
    )
    arrows = '<span class="pipeline-arrow" aria-hidden="true">&rarr;</span>'.join([""] * 5)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(product['name'])} &middot; Download &middot; {esc(product['vendor'])}</title>
<meta name="description" content="{esc(product['summary'])}">
<meta name="color-scheme" content="dark light">
<meta property="og:title" content="{esc(product['name'])} {esc(facts['version'])}">
<meta property="og:description" content="{esc(product['summary'])}">
<meta property="og:type" content="website">
<link rel="canonical" href="{esc(product['repository'])}">
<style>
{CSS}</style>
</head>
<body>

<header class="masthead">
  <div class="wrap">
    <a class="brand" href="#top">
      <span class="brand-mark" aria-hidden="true"></span>
      <span>{esc(product['name'])} <span class="brand-sub">by {esc(product['vendor'])}</span></span>
    </a>
    <span class="version-tag">v{esc(facts['version'])}</span>
  </div>
</header>

<main id="top">

  <section class="hero wrap">
    <h1>{esc(product['tagline'])}</h1>
    <p class="hero-lede">{esc(product['summary'])}</p>
    <p class="pipeline">
      {pipeline}<span class="pipeline-arrow" aria-hidden="true">{arrows}</span>
      <span class="pipeline-meta">L2&ndash;L4 decoded in Rust, stored in a local SQLite database.</span>
    </p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="#platform-{esc(manifest['platforms'][0]['id'])}">
        <span class="btn-label">Get {esc(product['name'])}</span>
        <span class="btn-file">Windows &middot; Linux &middot; macOS &middot; Android</span>
      </a>
      <a class="btn btn-ghost" href="#build">
        <span class="btn-label">Build from source</span>
        <span class="btn-file">Rust 1.95+ &middot; Node 20+</span>
      </a>
    </div>
  </section>

  <div class="wrap">
    {render_release_notice(manifest)}

    <section id="downloads">
      <h2>Download</h2>
      {render_platform_nav(manifest, None)}
      {platforms_html}
    </section>

    <section class="section" id="features">
      <h2>What it does</h2>
      {render_features(manifest)}
    </section>

    {render_not_implemented(manifest)}
    {render_cli(manifest)}
    {render_build_from_source(manifest)}
    {render_verification(manifest)}
    {render_faq(manifest)}
  </div>

</main>

{render_footer(manifest)}

</body>
</html>
"""
    return html_doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the page would change. For CI.",
    )
    args = parser.parse_args()

    try:
        manifest = read_manifest(MANIFEST_PATH)
        facts = verify_against_repository(manifest)
    except ManifestError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        rendered = build_html(manifest, facts)
        verify_internal_anchors(rendered)
    except ManifestError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.check:
        existing = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if existing != rendered:
            print(
                f"error: {args.out.relative_to(REPO_ROOT)} is stale. "
                "Run: python tools/generate-download-site.py",
                file=sys.stderr,
            )
            return 1
        print(f"{args.out.name} is up to date")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered, encoding="utf-8", newline="\n")

    print(f"Read {MANIFEST_PATH.relative_to(REPO_ROOT)}")
    print(
        f"  version {facts['version']}, {len(manifest['platforms'])} platforms, "
        f"{sum(len(p['artifacts']) for p in manifest['platforms'])} artifacts, "
        f"{'published' if manifest['release'].get('published') else 'not yet published'}"
    )
    print(f"Wrote {args.out} ({len(rendered) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())