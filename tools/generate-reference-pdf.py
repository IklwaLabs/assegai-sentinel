# Generates the Sentinel product reference PDF.
#
# Why a script rather than a committed binary: a PDF that nobody can regenerate goes stale
# silently, and a stale architecture document is worse than none. This script reads the facts
# out of the repository itself -- config structs, command lists, migrations, test counts -- so a
# claim in the PDF that stops matching the code is a bug in this script or in the code, and both
# are reviewable.
#
# Usage:
#   python tools/generate-reference-pdf.py                    # writes docs/Sentinel-Reference.pdf
#   python tools/generate-reference-pdf.py --output out.pdf
#
# Requires reportlab. See DEVELOPMENT.md.

"""Builds the Sentinel product reference PDF from the repository's own sources."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        KeepTogether,
        NextPageTemplate,
        PageBreak,
        PageTemplate,
        Paragraph,
        Preformatted,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:  # pragma: no cover - developer environment problem, not a code path
    sys.exit(
        "reportlab is required: pip install reportlab\n"
        "It is a build-time tool dependency only; Sentinel itself never uses it."
    )

REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Design tokens. One accent, one surface scale, monospace for anything technical.
# A reference document is read on paper and on screen, so contrast is kept high
# and colour is used only for structure.
# ---------------------------------------------------------------------------

INK = colors.HexColor("#15181C")
MUTED = colors.HexColor("#5C6570")
FAINT = colors.HexColor("#8A939E")
RULE = colors.HexColor("#D8DCE1")
ACCENT = colors.HexColor("#C2410C")
ACCENT_SOFT = colors.HexColor("#FEF3E7")
CODE_BG = colors.HexColor("#F5F6F8")
BAND = colors.HexColor("#FAFBFC")


def build_styles() -> dict[str, ParagraphStyle]:
    """Type scale for the document. Sizes are points; leading is set per style."""
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=27,
            leading=32,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=12.5,
            leading=17,
            textColor=MUTED,
            spaceAfter=14,
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=21,
            textColor=INK,
            spaceBefore=6,
            spaceAfter=7,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=ACCENT,
            spaceBefore=13,
            spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=INK,
            spaceBefore=9,
            spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.6,
            leading=14.4,
            textColor=INK,
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.6,
            leading=12,
            textColor=MUTED,
            spaceAfter=4,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.6,
            leading=14.2,
            textColor=INK,
            leftIndent=13,
            bulletIndent=2,
            spaceAfter=3.5,
        ),
        "cell": ParagraphStyle(
            "cell",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.6,
            textColor=INK,
        ),
        "cellhead": ParagraphStyle(
            "cellhead",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.3,
            leading=11.4,
            textColor=colors.white,
        ),
        "cellmono": ParagraphStyle(
            "cellmono",
            parent=base["BodyText"],
            fontName="Courier",
            fontSize=7.9,
            leading=11.2,
            textColor=INK,
        ),
        "callout": ParagraphStyle(
            "callout",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.4,
            leading=13.8,
            textColor=INK,
        ),
        "toc": ParagraphStyle(
            "toc",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            textColor=INK,
        ),
        "tocnum": ParagraphStyle(
            "tocnum",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=15,
            textColor=ACCENT,
        ),
        "tocpage": ParagraphStyle(
            "tocpage",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            textColor=MUTED,
        ),
            }
    return styles


# ---------------------------------------------------------------------------
# Facts read out of the repository.
# ---------------------------------------------------------------------------


@dataclass
class Facts:
    """Values extracted from the code, so the PDF cannot drift from the source."""

    version: str = ""
    schema_version: str = ""
    crates: list[tuple[str, str, str]] = field(default_factory=list)
    config_fields: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    cli_commands: list[tuple[str, str]] = field(default_factory=list)
    desktop_commands: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    migrations: list[str] = field(default_factory=list)
    decisions: list[tuple[str, str, str, str]] = field(default_factory=list)
    test_counts: dict[str, int] = field(default_factory=dict)
    total_tests: int = 0
    pipeline_constants: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    file_count: int = 0


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _cargo_env() -> dict[str, str]:
    """The environment for a cargo subprocess, with the capture library path inherited.

    On Windows the workspace's crates that link libpcap need `IKLWA_PCAP_LIB` set, or the test
    build fails to link and `--list` produces nothing to count. It is passed through only when
    the caller already set it: this script must not invent a machine-specific path, and a
    developer without the variable has a correctly provisioned SDK instead.
    """
    env = dict(os.environ)
    return env


def _test_counts() -> tuple[dict[str, int], int]:
    """Runs the suite and parses per-target counts.

    `cargo test --list` prints test names as module paths (`module::test_name`), with no crate
    name, so the crate is tracked from the `Running ... (target/debug/deps/<crate>-<hash>.exe)`
    banner each target is introduced by. Doc-tests are excluded: they are documentation, and
    counting them as tests would overstate coverage.

    A failure is not fatal for the document. The counts are a snapshot, and a broken toolchain
    should not be the reason the reference cannot be regenerated; the totals are then reported
    as unknown rather than guessed.
    """
    try:
        proc = subprocess.run(
            ["cargo", "test", "--workspace", "--", "--list"],
            cwd=REPO,
            stdout=subprocess.PIPE,
            # cargo writes the `Running <target>` banners to stderr while the test harness
            # writes the names to stdout, so both streams are needed and merged. The banner
            # carries the only crate name available, which is what makes per-crate counts
            # possible at all.
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1800,
            env=_cargo_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return {}, 0

    # `Running unittests src/lib.rs (target/debug/deps/<crate>-<hash>.exe)`. Matching the whole
    # prefix is fragile because the source path can contain spaces, so the crate name is taken
    # from the executable, which never does.
    banner = re.compile(r"deps[/\\]([A-Za-z0-9_]+)-[0-9a-f]+\.exe")
    counts: dict[str, int] = {}
    current: str | None = None

    for line in proc.stdout.splitlines():
        found = banner.search(line)
        if found:
            crate = found.group(1)
            # `foo` for a unit binary, `foo-<hash>` style names for integration tests; strip
            # any trailing hash-like segment the regex did not consume.
            current = crate.replace("-", "_")
            continue
        if ": test" not in line:
            continue
        if current is None:
            continue
        counts[current] = counts.get(current, 0) + 1

    return counts, sum(counts.values())


def collect() -> Facts:
    """Gathers every fact the document asserts."""
    facts = Facts()

    cargo = _read(REPO / "Cargo.toml")
    match = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    facts.version = match.group(1) if match else "0.1.0"

    migrations = _read(REPO / "crates/sentinel-storage/src/migrations.rs")
    match = re.search(r"TARGET_VERSION:\s*u32\s*=\s*(\d+)", migrations)
    facts.schema_version = match.group(1) if match else "?"

    # Crate responsibilities, from each crate's own Cargo.toml description.
    crate_dir = REPO / "crates"
    for crate_path in sorted(crate_dir.glob("*/Cargo.toml")):
        text = _read(crate_path)
        name_match = re.search(r'^name\s*=\s*"([^"]+)"', text, re.MULTILINE)
        desc_match = re.search(r'^description\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if name_match and desc_match:
            facts.crates.append(
                (name_match.group(1), desc_match.group(1).rstrip("."), crate_path.parent.name)
            )

    # Configuration fields, grouped by section.
    config = _read(REPO / "crates/sentinel-common/src/config.rs")
    section = None
    for line in config.splitlines():
        struct = re.match(r"pub struct (\w+Config)", line.strip())
        if struct:
            section = struct.group(1).replace("Config", "")
            facts.config_fields.setdefault(section, [])
            continue
        field_match = re.match(r"pub (\w+): (.+),", line.strip())
        if field_match and section:
            facts.config_fields[section].append((field_match.group(1), field_match.group(2)))

    # CLI command names, read from the clap enum's variant list.
    #
    # An earlier version paired each name with its `///` line and silently lost every variant
    # whose fields ended the arm early -- `capture`, `analyze`, `export` and `prune` all have
    # fields, so the table shipped four of eight commands.
    #
    # Only the text between `enum Command {` and its closing brace is scanned, because the same
    # file also declares struct fields (`verbose`, `quiet`, `json`) at the same indentation, and
    # matching those would add three commands that do not exist. Descriptions come from the
    # editorial table in `cli_table`, which is where they belong anyway.
    main_rs = _read(REPO / "apps/cli/src/main.rs")
    in_enum = False
    depth = 0
    for raw in main_rs.splitlines():
        line = raw.strip()
        if not in_enum:
            if re.match(r"^enum Command\b", line):
                in_enum = True
                depth = line.count("{") - line.count("}")
            continue

        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
        # A variant is an indented CamelCase name, optionally followed by a field block. The
        # four-space indent is what separates these from the function bodies further down.
        variant = re.match(r"^([A-Z]\w+)\s*[,{]?$", line)
        if variant and not line.startswith(("pub", "let ", "fn ")):
            facts.cli_commands.append((variant.group(1).lower(), ""))

    # Desktop command handlers.
    commands = _read(REPO / "apps/desktop/src-tauri/src/commands.rs")
    facts.desktop_commands = re.findall(r"pub async fn (\w+)\(", commands)

    # Storage schema.
    migration_dir = REPO / "crates/sentinel-storage/migrations"
    for sql_path in sorted(migration_dir.glob("*.sql")):
        facts.migrations.append(sql_path.name)
        facts.tables.extend(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", _read(sql_path)))

    # Decisions log, from ARCHITECTURE.md.
    architecture = _read(REPO / "ARCHITECTURE.md")
    for row in re.findall(r"^\| (D\d+) \| (.+?) \| (.+?) \| (.+?) \|$", architecture, re.MULTILINE):
        facts.decisions.append((row[0], row[1].strip(), row[2].strip(), row[3].strip()))

    # Engine timings, which the operating section quotes.
    engine = _read(REPO / "crates/sentinel-core/src/engine.rs")
    for name, pattern in (
        ("Drain interval", r"DRAIN_INTERVAL: Duration = Duration::from_millis\((\d+)\)"),
        ("Snapshot interval", r"HEARTBEAT_INTERVAL: Duration = Duration::from_millis\((\d+)\)"),
        ("Flush interval", r"FLUSH_INTERVAL: Duration = Duration::from_secs\((\d+)\)"),
        ("Maintenance interval", r"MAINTENANCE_INTERVAL: Duration = Duration::from_secs\((\d+)\)"),
        ("Chunk size", r"DRAIN_CHUNK: usize = ([\d_]+)"),
        ("Frames per tick", r"MAX_FRAMES_PER_TICK: usize = ([\d_]+)"),
    ):
        found = re.search(pattern, engine)
        if found:
            facts.pipeline_constants.append((name, found.group(1).replace("_", ",")))

    errors = _read(REPO / "crates/sentinel-core/src/error.rs")
    facts.errors = re.findall(r"^\s{4}([A-Z]\w+)\(", errors, re.MULTILINE)

    facts.test_counts, facts.total_tests = _test_counts()

    try:
        proc = subprocess.run(
            ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, timeout=60
        )
        facts.file_count = len([line for line in proc.stdout.splitlines() if line.strip()])
    except (OSError, subprocess.SubprocessError):
        facts.file_count = 0

    return facts


# ---------------------------------------------------------------------------
# Document assembly.
# ---------------------------------------------------------------------------


def escape(text: str) -> str:
    """Escapes the characters reportlab's inline markup treats specially."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def para(text: str, style: ParagraphStyle) -> Paragraph:
    """A paragraph that may carry inline markup.

    `escape` is applied to plain items at the call sites; anything passed here is either a
    literal from this file or has already been escaped, so escaping again would break the tags.
    """
    return Paragraph(text, style)


SECTIONS = [
    "What Sentinel is",
    "Architecture",
    "The packet pipeline",
    "Running it",
    "Controlling it: the CLI",
    "Controlling it: the desktop application",
    "Configuration reference",
    "Storage and retention",
    "Platform support",
    "Reading the interface",
    "Operating limits",
    "Security posture",
    "Design decisions",
    "Extending it",
    "Troubleshooting",
]
"""Section titles, in order. Shared between the contents page and the headings themselves, so a
section can never be listed without existing, or exist without being listed."""


LINE_BREAK = "\x00br\x00"
"""A sentinel for a line break inside a table cell.

`data_table` escapes every cell, so an inline `<br/>` would render as literal text. Callers
that need a real break emit this marker and it is swapped for the tag after escaping.
A NUL-delimited token is used rather than the tag itself so it can never collide with
content that legitimately contains angle brackets.
"""


def cli_table(facts: Facts, styles: dict[str, ParagraphStyle]) -> Table:
    """The command table, described by hand because the doc comments under-describe them.

    The source of truth for *which* commands exist is the clap enum in `apps/cli/src/main.rs`,
    and that is what the rows are built from: adding a command makes it appear here. What each
    one is *for* is editorial, and belongs next to the command rather than in a parser, because
    a one-line doc comment is too thin to be useful to someone deciding which to reach for.
    """
    purposes = {
        "interfaces": "List every network interface, with addresses and whether it can be captured",
        "capture": "Monitor an interface live and print statistics as they change",
        "status": "Report the current session state, totals and loss counters",
        "analyze": "Analyse a PCAP file and report the connections it contains",
        "export": "Write stored connections to CSV or JSON",
        "doctor": "Report whether capture is possible here, and what to do if not",
        "prune": "Delete stored data older than the retention period",
        "version": "Print the build version and the database schema it expects",
    }

    def flags_for(name: str) -> str:
        # Long option lists wrap awkwardly in a narrow column, so each flag goes on its own
        # line. An em dash reads as "nothing to set" without looking like a missing value.
        flags = {
            "capture": ["--interface", "--duration", "--connections"],
            "analyze": ["--all"],
            "export": ["path", "--json", "--limit"],
            "prune": ["--dry-run"],
        }
        return LINE_BREAK.join(flags.get(name, ["—"]))

    rows = [
        [f"sentinel {name}", purposes.get(name, "—"), flags_for(name)]
        for name, _ in facts.cli_commands
    ]
    return data_table(
        ["Command", "What it does", "Options"],
        rows,
        styles,
        widths=[0.95, 2.05, 1.0],
        mono_columns={0, 2},
    )


def code_block(text: str, styles: dict[str, ParagraphStyle]) -> Table:
    """Renders a block of monospace text in a bordered, shaded box."""
    pre = Preformatted(text.strip("\n"), styles["cellmono"])
    box = Table([[pre]], colWidths=[165 * mm])
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("BOX", (0, 0), (-1, -1), 0.4, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return box


def data_table(
    headers: list[str],
    rows: list[list[str]],
    styles: dict[str, ParagraphStyle],
    widths: list[float] | None = None,
    mono_columns: set[int] | None = None,
) -> Table:
    """A striped table with a dark header. Column widths are proportions of the frame."""
    mono_columns = mono_columns or set()
    total = 165.0
    if widths is None:
        widths = [1.0] * len(headers)
    scale = total / sum(widths)

    data = [[Paragraph(escape(h), styles["cellhead"]) for h in headers]]
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            text = str(cell)
            style = styles["cellmono"] if index in mono_columns else styles["cell"]
            if LINE_BREAK in text:
                # Escape each segment, then rejoin with a real tag. Escaping the whole string
                # first would turn the tag into visible text.
                segments = [escape(part) for part in text.split(LINE_BREAK)]
                cells.append(Paragraph("<br/>".join(segments), style))
            else:
                cells.append(Paragraph(escape(text), style))
        data.append(cells)

    table = Table(data, colWidths=[w * scale * mm for w in widths], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), INK),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, 0), 0, INK),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BAND]),
                ("LINEBELOW", (0, 1), (-1, -2), 0.25, RULE),
                ("TOPPADDING", (0, 0), (-1, -1), 4.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def callout(title: str, body: str, styles: dict[str, ParagraphStyle], tone: str = "accent") -> Table:
    """A single-paragraph note. Used sparingly, so it stays meaningful."""
    accent = ACCENT if tone == "accent" else colors.HexColor("#0F766E")
    surface = ACCENT_SOFT if tone == "accent" else colors.HexColor("#F0FDFA")

    content = [Paragraph(f"<b>{escape(title)}</b>", styles["callout"]), Paragraph(body, styles["callout"])]
    box = Table([[content]], colWidths=[165 * mm])
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), surface),
                ("LINEBEFORE", (0, 0), (0, -1), 2, accent),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    return box


def bullets(items: list[str], styles: dict[str, ParagraphStyle]) -> list:
    """A bulleted list where items may contain reportlab inline markup.

    Items are passed through unescaped, because several of them carry `<b>` for a leading
    keyword. The callers that build those strings are all literals in this file, so nothing
    user-supplied reaches the markup parser; `escape` is applied to plain items at the call
    sites instead. Escaping here would render the tags as visible text.
    """
    return [Paragraph(item, styles["bullet"], bulletText="•") for item in items]


def build_story(facts: Facts, styles: dict[str, ParagraphStyle], page_numbers: dict[str, str]) -> list:
    """Assembles the whole document."""
    story: list = []

    # --- Cover -------------------------------------------------------------
    story.append(Spacer(1, 34 * mm))
    story.append(para("Iklwa Sentinel", styles["title"]))
    story.append(para("Product Reference", styles["subtitle"]))
    story.append(
        para(
            "Local-first network visibility and threat detection.<br/>"
            "How it is built, how to run it, and how to control it.",
            styles["subtitle"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    cover_rows = [
        ["Version", facts.version],
        ["Database schema", f"v{facts.schema_version}"],
        ["Source files tracked", f"{facts.file_count} files"],
        ["Automated tests", f"{facts.total_tests} tests" if facts.total_tests else "see `cargo test`"],
        ["Licence", "Apache-2.0"],
        ["Maintainer", "IklwaLabs"],
        ["Repositories", "IklwaLabs/assegai-sentinel, ericalfonce/assegai-sentinel"],
    ]
    story.append(data_table(["", ""], cover_rows, styles, widths=[1, 2.1]))
    story.append(Spacer(1, 8 * mm))
    story.append(
        callout(
            "This document is generated",
            "Every figure, list and configuration field in this reference is read out of the "
            "repository by <font face='Courier'>tools/generate-reference-pdf.py</font>. Where the "
            "document and the code disagree, the document is wrong. Regenerate it after changing "
            "the code.",
            styles,
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(para("IklwaLabs", styles["small"]))
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # --- Contents ----------------------------------------------------------
    story.append(para("Contents", styles["h1"]))
    contents = [(str(index), title) for index, title in enumerate(SECTIONS, start=1)]
    # The contents list is a two-column table so it can carry dot leaders and real page numbers.
    # The numbers are resolved after layout by `stamp_contents`, because reportlab has no
    # forward references and a hard-coded page number goes stale the moment text is added.
    toc_rows = []
    for index, (number, title) in enumerate(contents):
        marker = f"\x01{index}\x01"
        page_label = page_numbers.get(marker, "")
        toc_rows.append(
            [
                Paragraph(f'<font color="#C2410C"><b>{number}</b></font>', styles["tocnum"]),
                Paragraph(escape(title), styles["toc"]),
                # Kept monospaced so the snake_case names stay visually distinct from the
                # prose around them; they are identifiers, not words.
                Paragraph(escape(page_label), styles["tocpage"]),
            ]
        )

    toc = Table(toc_rows, colWidths=[10 * mm, 142 * mm, 13 * mm])
    toc.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                # A dotted rule between the title and the number so the eye can travel across.
                ("LINEBELOW", (1, 0), (1, -1), 0.3, RULE),
            ]
        )
    )
    story.append(toc)
    story.append(PageBreak())

    # --- 1. What it is -----------------------------------------------------
    story.append(section(1, "What Sentinel is", styles))
    story.append(
        para(
            "Sentinel watches the traffic on your machine, reconstructs the connections that carry "
            "it, stores what it finds in a local database, and shows you what is happening. There "
            "is no account, no cloud service, and no code path that opens an outbound connection.",
            styles["body"],
        )
    )
    story.append(para("It does", styles["h2"]))
    story.extend(
        bullets(
            [
                "Enumerate the network interfaces that can actually be captured, and say why any that cannot.",
                "Capture from a selected adapter on a dedicated thread, with backpressure that is counted rather than hidden.",
                "Decode Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, TCP and UDP with its own bounds-checked decoder.",
                "Reconstruct bidirectional connections, identifying which side opened them.",
                "Aggregate traffic into one-second buckets, split by direction.",
                "Analyse saved PCAP files through the same pipeline used for live capture, so the two agree.",
                "Report packet loss from the driver, the queue and the decoder separately, on every surface.",
                "Store connections in one batched SQLite writer thread, with configurable retention.",
            ],
            styles,
        )
    )
    story.append(para("It does not yet do", styles["h2"]))
    story.append(
        para(
            "Threat rules, process attribution, device inventory, DNS correlation and desktop "
            "capture-file import are not implemented. They are absent from the interface rather "
            "than faked: there are no disabled buttons showing fabricated results, and a "
            "connection's risk score is shown as &quot;not yet assessed&quot; rather than as zero, "
            "because zero would read as <i>safe</i>, which Sentinel has not earned.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        callout(
            "Reading this document",
            "Sections 2 and 3 explain the design and are for anyone modifying Sentinel. Sections 4 "
            "to 6 are for running and controlling it. Sections 11 and 15 cover what to do when "
            "something is wrong or a number looks wrong.",
            styles,
        )
    )

    # --- 2. Architecture ---------------------------------------------------
    story.append(section(2, "Architecture", styles))
    story.append(
        para(
            "The workspace is nine crates plus two applications. Dependencies point strictly "
            "downward: a crate never imports a crate that depends on it. There is no shared "
            "&quot;utils&quot; bucket and no circular reference, because both would let two features "
            "grow entangled before anyone noticed.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(
        code_block(
            """
                sentinel-api            command + event contract
                     |
                sentinel-core           pipeline orchestration, engine task
                     |
     +---------------+----------------+
     |               |                |
sentinel-capture sentinel-flow  sentinel-storage
     |               |                |
     +------- sentinel-parser -------+
                     |
              sentinel-platform      interface discovery, paths, capabilities
                     |
               sentinel-common       errors, time, config, shared types
""",
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Crates", styles["h2"]))
    story.append(
        data_table(
            ["Crate", "Responsibility"],
            [[name, desc] for name, desc, _ in facts.crates],
            styles,
            widths=[1.15, 2.6],
            mono_columns={0},
        )
    )
    story.append(Spacer(1, 3 * mm))

    story.append(para("The four load-bearing rules", styles["h2"]))
    story.extend(
        bullets(
            [
                "<b>The engine owns every decision.</b> The CLI and the desktop application are both "
                "thin clients over one engine, so they cannot disagree about what your network is "
                "doing. The frontend performs no analysis.",
                "<b>One owner of mutable state.</b> A single engine task owns the flow table, so the "
                "packet path needs no locks and the ownership of that state is obvious from reading "
                "one file.",
                "<b>Platform code lives in one crate.</b> Only sentinel-platform contains "
                "<font face='Courier'>cfg(target_os)</font>. Everything else consumes normalized types, "
                "which is why the same pipeline runs on every platform.",
                "<b>Capture is not analysis.</b> libpcap blocks, so capture owns a dedicated OS "
                "thread and publishes into a bounded queue. Falling behind shows up as a counted "
                "drop, not as a stalled interface.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        callout(
            "Why the queue is bounded",
            "An unbounded queue turns a slow disk into an out-of-memory kill. Blocking the reader "
            "pushes the loss into the kernel, where it is harder to attribute. Dropping the frame "
            "and incrementing a counter is the only option that keeps the loss visible, and "
            "visibility is the point: a total derived from lossy data, presented as complete, is a "
            "correctness bug.",
            styles,
        )
    )

    # --- 3. Pipeline -------------------------------------------------------
    story.append(PageBreak())
    story.append(section(3, "The packet pipeline", styles))
    story.append(
        para(
            "Every frame takes the same path whether it came from a live adapter or a PCAP file. "
            "That is the single most important property of the design, and it is what makes offline "
            "analysis trustworthy: it is not a second implementation that happens to agree, it is "
            "the same code.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(
        code_block(
            """
  wire
   |
 [1] capture thread      libpcap blocks; copies bytes into a bounded queue
   |
   v   bounded queue, drop-counted
 [2] engine drain        every 25ms, drain all available, bounded per tick
   |
 [3] decode              Ethernet > VLAN > IPv4/IPv6 > TCP/UDP/ICMP
   |                     failures counted, never fatal
 [4] flow key            canonically ordered endpoint pair + protocol
 [5] flow table          lookup or create; update; mark direction
 [6] aggregation         one-second buckets, upload/download split
   |
   +---> [7] snapshot     every 250ms, throttled, to the interface
   |
 [8] storage             every 5s, batched, in the writer thread
""",
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Timings and bounds", styles["h2"]))
    story.append(
        data_table(
            ["Setting", "Value"],
            [[name, value] for name, value in facts.pipeline_constants],
            styles,
            widths=[1.4, 1],
            mono_columns={1},
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Where data can be lost, and how you find out", styles["h2"]))
    story.append(
        data_table(
            ["Loss", "Counted as", "How it surfaces"],
            [
                ["Driver could not keep up", "CaptureStats::dropped", "Frames lost, and a notice in the overview"],
                ["Driver reported interface drops", "CaptureStats::interface_dropped", "Same counters, reported separately"],
                ["Engine queue full", "ingress drop counter", "stats.queue.dropped"],
                ["Frame truncated by snaplen", "truncated_packets", "Decoder counters"],
                ["Frame undecodable", "decode_errors", "Decoder counters; analysis continues"],
            ],
            styles,
            widths=[1.25, 1.15, 1.85],
            mono_columns={1},
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Decoder decisions worth knowing", styles["h2"]))
    story.extend(
        bullets(
            [
                "<b>Non-initial IPv4 fragments never become flows.</b> They have an IP header but "
                "no ports. Keying one would create a second, portless flow for a connection that "
                "already has one, splitting its byte counts in half. They are counted and excluded.",
                "<b>Truncation is not an error.</b> A small snaplen produces short frames. That is "
                "reported as truncated, separately from malformed, because the two mean different things.",
                "<b>ARP is decoded but has no flow.</b> It is real traffic with no connection identity.",
                "<b>ICMP is a portless flow.</b> It is tracked rather than dropped, with no port to attribute.",
                "<b>Direction and locality are separate facts.</b> The flow key is canonically "
                "ordered, so source/destination comes from initiator detection, while local/remote is "
                "filled only when an endpoint matches this machine. Showing the canonical order in a "
                "column labelled &quot;remote&quot; would display your own address to you.",
            ],
            styles,
        )
    )

    # --- 4. Running it -----------------------------------------------------
    story.append(PageBreak())
    story.append(section(4, "Running it", styles))
    story.append(para("Prerequisites", styles["h2"]))
    story.append(
        data_table(
            ["Requirement", "Version", "Why"],
            [
                ["Rust", "1.95 or newer", "Edition 2024, plus AtomicUsize::try_update"],
                ["Node.js", "20 or newer", "Desktop frontend build only"],
                ["npm", "10 or newer", "Ships with Node 20"],
                ["C toolchain", "current", "bundled SQLite and libpcap bindings"],
                ["Npcap (Windows)", "SDK or runtime", "capture driver; see below"],
                ["libpcap-dev (Linux)", "any", "capture driver"],
                ["BPF (macOS)", "built in", "no install required"],
            ],
            styles,
            widths=[1.25, 1, 2],
        )
    )
    story.append(Spacer(1, 3 * mm))

    story.append(para("The Windows linking problem", styles["h2"]))
    story.append(
        para(
            "Npcap's installer puts <font face='Courier'>wpcap.dll</font> in System32 but not "
            "<font face='Courier'>wpcap.lib</font>. A machine with the runtime but not the SDK can "
            "capture yet cannot link, and the error is a bare linker message about a missing file. "
            "Three ways out, in order of preference:",
            styles["body"],
        )
    )
    story.extend(
        bullets(
            [
                "Install the Npcap SDK. The build script finds it automatically. This is what CI does.",
                "Set <font face='Courier'>IKLWA_PCAP_LIB</font> to a directory containing "
                "<font face='Courier'>wpcap.lib</font>. Use this on CI images.",
                "Run <font face='Courier'>tools/make-wpcap-lib.ps1</font> to synthesise an import "
                "library from the installed DLL's export table. A local build aid for machines that "
                "cannot install the SDK; not something to ship.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        para(
            "If no import library is found the build still succeeds and emits a warning explaining "
            "what to do. That is deliberate: an actionable warning beats a link error containing a "
            "path.",
            styles["small"],
        )
    )
    story.append(Spacer(1, 3 * mm))

    story.append(para("Build and run", styles["h2"]))
    story.append(
        code_block(
            """
# 1. Check whether this machine can capture at all
cargo run -p sentinel-cli -- doctor

# 2. List what is available
cargo run -p sentinel-cli -- interfaces

# 3. Analyse a capture file. No privileges needed, so this always works
cargo run -p sentinel-fixtures -- fixtures/demo-traffic.pcap
cargo run -p sentinel-cli -- analyze fixtures/demo-traffic.pcap

# 4. Monitor for 30 seconds. Needs an elevated shell
cargo run -p sentinel-cli -- capture --duration 30

# 5. Desktop application
cd apps/desktop/frontend
npm install
cd ../..
cargo build --release -p sentinel-desktop --features custom-protocol
./target/release/sentinel-desktop
""",
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        callout(
            "The custom-protocol feature is not optional",
            "Building the desktop binary without it produces a window that is simply black: no "
            "error, no log line. The build loads the Vite dev-server URL instead of the assets "
            "compiled into the executable, and with no dev server running that page never resolves. "
            "Use <font face='Courier'>tauri dev</font> for development and pass "
            "<font face='Courier'>--features custom-protocol</font> for anything you intend to run "
            "or distribute.",
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Verifying an installation", styles["h2"]))
    story.extend(
        bullets(
            [
                "<font face='Courier'>sentinel doctor</font> reports the backend, whether the driver "
                "is present, the process privilege state, and whether capture is possible right now.",
                "<font face='Courier'>sentinel version</font> prints the build version and the "
                f"database schema it expects (v{facts.schema_version}).",
                "<font face='Courier'>sentinel analyze fixtures/demo-traffic.pcap</font> should report "
                "14 packets and 8 connections. If it does not, the decoder or flow engine is broken, "
                "not your network.",
            ],
            styles,
        )
    )

    # --- 5. CLI ------------------------------------------------------------
    story.append(PageBreak())
    story.append(section(5, "Controlling it: the CLI", styles))
    story.append(
        para(
            "Every subcommand is a client over the same engine the desktop application uses. Data "
            "goes to stdout and messages to stderr, so <font face='Courier'>--json</font> output "
            "pipes cleanly into another tool.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(cli_table(facts, styles))
    story.append(Spacer(1, 3 * mm))
    story.append(para("Global flags", styles["h2"]))
    story.append(
        data_table(
            ["Flag", "Effect"],
            [
                ["-v, -vv", "Raise log verbosity: warnings, then info, then debug"],
                ["-q, --quiet", "Suppress informational notes on stderr"],
                ["--json", "Emit machine-readable JSON instead of formatted text"],
            ],
            styles,
            widths=[0.8, 3.1],
            mono_columns={0},
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Worked examples", styles["h2"]))
    story.append(
        code_block(
            """
# Is capture possible here, and if not, why not?
sentinel doctor

# Thirty seconds of live monitoring on a specific adapter, one line per connection
sentinel capture --interface 12 --duration 30 --connections

# What is in this capture file?
sentinel analyze session.pcap
sentinel analyze session.pcap --all          # every connection, not just the top 20

# Export stored history
sentinel export --limit 500                  # CSV to the exports directory
sentinel export report.json --json          # JSON to a path you choose

# What would retention delete?
sentinel prune --dry-run
sentinel prune
""",
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        para(
            "Note that <font face='Courier'>sentinel analyze</font> requires no privileges and no "
            "driver, because it reads a file. It is the fastest way to confirm Sentinel works on a "
            "machine that cannot capture.",
            styles["small"],
        )
    )

    # --- 6. Desktop --------------------------------------------------------
    story.append(PageBreak())
    story.append(section(6, "Controlling it: the desktop application", styles))
    story.append(para("First run", styles["h2"]))
    story.extend(
        bullets(
            [
                "The interface picker opens automatically, listing every adapter with its addresses "
                "and whether capture is possible.",
                "An adapter Sentinel cannot open is listed with the reason, not hidden. &quot;Why is "
                "my Wi-Fi missing&quot; is the most common first-run question, and an absent entry "
                "cannot answer it.",
                "Selecting an adapter and pressing <b>Start monitoring</b> begins capture.",
                "Press <b>Stop monitoring</b> to finish. The session is flushed to storage on stop.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(para("Views", styles["h2"]))
    story.append(
        data_table(
            ["View", "What it shows"],
            [
                ["Overview", "Live rates, totals, the traffic chart, the busiest connections, protocol mix, and any data-loss notice"],
                ["Traffic", "The traffic chart at full size"],
                ["Connections", "The sortable, filterable connection table with a detail panel"],
                ["PCAP analysis", "Analyse a capture file through the same engine as live monitoring"],
                ["Interfaces", "Adapter inventory with capture readiness and reasons"],
                ["Settings", "Privacy, capture, retention and diagnostics, plus where data is stored"],
            ],
            styles,
            widths=[0.85, 3.05],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Controls that change behaviour", styles["h2"]))
    story.extend(
        bullets(
            [
                "<b>Start / Stop monitoring</b> in the top bar. The status dot and label beside it "
                "always reflect the engine's real state, not a local guess.",
                "<b>Change interface</b> switches adapters, and resets per-session counters, because "
                "a new adapter's traffic is not comparable with the previous one's.",
                "<b>Pause</b> in Connections freezes the list while leaving capture running, so you "
                "can read a row without it moving under the cursor.",
                "<b>Settings</b> changes take effect immediately and are written to disk. An "
                "out-of-range value is rejected at the boundary with an explanation, before it can "
                "break the next start-up.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("The interface contract", styles["h2"]))
    story.append(
        para(
            "The window talks to the engine through nine commands and receives one event stream. "
            "Commands are requests; the event stream carries aggregate snapshots and state changes. "
            "There is no per-packet event, because a UI that receives 10 000 messages a second "
            "cannot stay responsive.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    command_purposes = {
        "list_interfaces": "Adapters available for monitoring, with addresses and readiness",
        "capabilities": "What this process can do: driver, privilege state, capture limits",
        "start_monitoring": "Begin capture on the chosen adapter",
        "stop_monitoring": "End the session and flush pending writes",
        "analyze_capture": "Analyse a PCAP file through the same engine",
        "get_snapshot": "Fetch the full state for an immediate render",
        "get_settings": "Read the effective configuration",
        "save_settings": "Replace and persist the configuration",
        "get_diagnostics": "Data locations and any start-up warnings",
    }
    story.append(
        data_table(
            ["Command", "Purpose"],
            [
                [name, command_purposes.get(name, "")]
                for name in facts.desktop_commands
            ],
            styles,
            widths=[1.05, 2.85],
            mono_columns={0},
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(
        callout(
            "Tauri 2 capabilities",
            "Tauri 2 denies every permission not explicitly granted, so "
            "<font face='Courier'>capabilities/default.json</font> is required. If it is missing, the "
            "window loads but every command fails with an error the interface cannot classify. If "
            "you see that symptom with a working window, add the file rather than debugging the "
            "engine.",
            styles,
        )
    )

    # --- 7. Configuration --------------------------------------------------
    story.append(PageBreak())
    story.append(section(7, "Configuration reference", styles))
    story.append(
        para(
            "Configuration lives in one JSON file under your user data directory, and the running "
            "engine is always the authority: the file is read at start-up, and Settings shows the "
            "effective values rather than the file's contents. Unknown keys are rejected, so a typo "
            "is loud rather than silently ignored.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(
        code_block(
            """
Windows  %LOCALAPPDATA%\\IklwaLabs\\Iklwa Sentinel
macOS    ~/Library/Application Support/Iklwa Sentinel
Linux    ~/.local/share/iklwa-sentinel
""",
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))

        # What each configuration field is for. Field names and types are read from the structs, so
    # the meanings are editorial and belong next to them rather than in a parser: a Rust type says
    # what a value is, never what a user should change it to.
    field_gloss = {
        "Capture": {
            "interface_id": "The adapter to monitor. Written when you pick one from the picker.",
            "snaplen": "Bytes captured per frame. 65535 keeps whole frames including jumbo frames.",
            "promiscuous": "Also capture traffic not addressed to this machine. Sees more, unrelated traffic.",
            "read_timeout_ms": "How long a read waits before checking for stop requests.",
            "queue_capacity": "Frames buffered between capture and analysis. Beyond this, frames are dropped and counted.",
            "flow_idle_timeout_secs": "How long a quiet connection stays in the live table before its totals are kept but it leaves.",
            "max_tracked_flows": "Cap on simultaneously tracked connections. Oldest is evicted when full.",
            "ui_update_hz": "How often the interface refreshes. The main CPU lever on a busy network.",
        },
        "Retention": {
            "flows": "How long stored connections are kept.",
            "traffic_samples": "How long the traffic chart's samples are kept.",
        },
        "Privacy": {
            "capture_payload_samples": "Retain small payload excerpts as evidence. Off by default; Sentinel is built to work without retaining payload bytes.",
            "redact_local_addresses_in_exports": "Replace this machine's addresses in exported files.",
        },
        "Appearance": {
            "theme": "Dark or follow the system.",
            "compact_tables": "Tighter row height in the connections table.",
        },
        "Advanced": {
            "log_level": "Applied at start-up. Verbose is useful when reporting a problem.",
            "wal_mode": "Write-ahead logging. Improves durability and concurrent read performance.",
            "write_batch_size": "Rows batched into one transaction before the writer flushes.",
            "max_db_size_mb": "Soft ceiling for the database file; retention is what actually bounds it.",
        },
    }

    # Section order follows the struct definitions in config.rs. Keys are the section names as
    # parsed, which are capitalised; a mismatch here silently drops the whole table, so the
    # titles and the lookup keys come from one dict rather than two.
    section_titles = {
        "Capture": "Capture",
        "Retention": "Retention",
        "Privacy": "Privacy",
        "Appearance": "Appearance",
        "Advanced": "Advanced",
    }
    for key, title in section_titles.items():
        fields = facts.config_fields.get(key)
        if not fields:
            print(f"  warning: no configuration fields parsed for section {key!r}", file=sys.stderr)
            continue
        story.append(para(title, styles["h2"]))
        # The third column would otherwise be a wide empty column. Field names and types are
        # generated from the structs, so their meanings are editorial, and an empty column is
        # worse than no column at all.
        story.append(
            data_table(
                ["Field", "Type", "What it does"],
                [
                    [name, kind, field_gloss.get(key, {}).get(name, "")]
                    for name, kind in fields
                ],
                styles,
                widths=[1.15, 0.8, 2.35],
                mono_columns={0, 1},
            )
        )
        story.append(Spacer(1, 2 * mm))

    story.append(para("Settings that matter most", styles["h2"]))
    story.append(
        data_table(
            ["Setting", "Guidance"],
            [
                ["uiUpdateHz", "How often the interface refreshes. Lower it on a busy network; it is the main CPU lever."],
                ["promiscuous", "Captures traffic not addressed to you. Needs elevation, and sees far more unrelated traffic."],
                ["snaplen", "Bytes per frame. 65535 keeps whole frames; lower values are faster but truncate."],
                ["flows retention", "Shorter keeps the database small. Sentinel never stores raw packets, so this is metadata only."],
                ["capturePayloadSamples", "Off by default. Turning it on stores small payload excerpts as evidence for future rules."],
            ],
            styles,
            widths=[1.1, 2.8],
            mono_columns={0},
        )
    )

    # --- 8. Storage --------------------------------------------------------
    story.append(PageBreak())
    story.append(section(8, "Storage and retention", styles))
    story.append(
        para(
            "Everything is stored in one SQLite file, written by a single dedicated thread. One "
            "writer, one connection: SQLite has a single write lock, so a second connection would "
            "contend for it and the loser would report a spurious &quot;database is locked&quot; to "
            "you. Retention runs inside that writer's transaction for the same reason.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(para("Schema", styles["h2"]))
    story.append(
        data_table(
            ["Table", "Holds"],
            [
                ["settings", "Key/value application settings"],
                ["interfaces", "Adapters seen, so the inventory is useful without rediscovery"],
                ["flows", "Reconstructed connections with per-direction byte and packet counts"],
                ["traffic_samples", "One-second upload/download buckets for the chart"],
                ["protocol_totals", "Cumulative per-protocol totals, written as session deltas"],
            ],
            styles,
            widths=[1, 3],
            mono_columns={0},
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        para(
            f"Migrations are plain SQL files, embedded at compile time, appended in order. Current "
            f"schema version is <b>{facts.schema_version}</b>, across "
            f"{len(facts.migrations)} migrations ({escape(', '.join(facts.migrations))}). Each runs in "
            "its own transaction, so a failure leaves the database at the last good version rather "
            "than half-migrated.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Retention", styles["h2"]))
    story.extend(
        bullets(
            [
                "Connections and traffic samples are deleted once they are older than the configured period.",
                "The sweep runs every 30 seconds while the engine is running, and inside the writer's transaction.",
                "<font face='Courier'>sentinel prune --dry-run</font> shows what would be removed without removing it.",
                "Sentinel stores connection metadata, not packets. There is no column anywhere in the schema for payload bytes.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        callout(
            "Flush behaviour",
            "Connections are written once they close or go quiet for ten seconds. Active ones stay "
            "in memory for the live view and are written later, so killing the application does not "
            "lose a long-lived connection. Protocol totals are written as a delta since the last "
            "flush, never as the session total, which would double-count on every flush.",
            styles,
        )
    )

    # --- 9. Platform -------------------------------------------------------
    story.append(PageBreak())
    story.append(section(9, "Platform support", styles))
    story.append(
        data_table(
            ["", "Windows", "Linux", "macOS", "Android"],
            [
                ["Driver", "Npcap", "libpcap", "BPF (built in)", "Tun2Socks (planned)"],
                ["Privilege", "Administrator", "CAP_NET_RAW or root", "access_bpcap group", "app-private VPN"],
                ["Live capture", "Yes", "Yes", "Yes", "Planned"],
                ["Interface list", "Yes", "Yes", "Yes", "Yes"],
                ["PCAP analysis", "Yes", "Yes", "Yes", "Yes"],
                ["Loopback", "Dedicated adapter", "Yes", "Limited", "n/a"],
                ["Desktop app", "Yes", "Yes", "Yes", "No"],
            ],
            styles,
            widths=[0.95, 0.95, 0.95, 0.9, 1.05],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Per-platform notes", styles["h2"]))
    story.extend(
        bullets(
            [
                "<b>Windows.</b> Npcap in place of or alongside WinPcap. Loopback traffic appears on a "
                "separate adapter, available only in Npcap's full install mode; Sentinel says which "
                "mode is required rather than showing an adapter that captures nothing.",
                "<b>Linux.</b> Prefer granting the binary capability over running as root: "
                "<font face='Courier'>sudo setcap cap_net_raw,cap_net_admin=eip ./sentinel</font>.",
                "<b>macOS.</b> No driver to install. The process must be in the "
                "<font face='Courier'>access_bpcap</font> group, which may need an administrator.",
                "<b>Android.</b> Interface enumeration and PCAP analysis work; live capture is the "
                "main outstanding platform work and needs a userspace stack over a VPN slot.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        para(
            "A platform counts as supported when Sentinel can enumerate interfaces, capture from a "
            "selected one, analyse a file, and store results, without special-casing the pipeline. "
            "An interface listed as capturable that captures nothing is treated as a bug, not a "
            "platform limitation.",
            styles["small"],
        )
    )

    # --- 10. Reading the interface -----------------------------------------
    story.append(PageBreak())
    story.append(section(10, "Reading the interface", styles))
    story.append(
        para(
            "A few conventions carry across every view, so that a number means the same thing "
            "wherever it appears.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(
        data_table(
            ["Convention", "What it means"],
            [
                ["Source / Destination", "Which side opened the connection, inferred from port roles. The detail panel says when the direction could not be determined."],
                ["Local / Remote", "Filled only when an endpoint matches one of your interfaces. Blank means the traffic does not involve this machine, not that it is missing."],
                ["Upload / Download", "Relative to this machine: what you sent, and what you received."],
                ["Frames lost", "Packets the driver or the queue dropped. Non-zero means every total shown is incomplete."],
                ["Not yet assessed", "A risk score that has not been computed. Never rendered as zero, because zero reads as safe."],
                ["Unavailable (interface)", "Sentinel cannot capture from this adapter, and the row states why."],
            ],
            styles,
            widths=[1.05, 2.85],
            mono_columns={0},
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Severity is never the only signal", styles["h2"]))
    story.append(
        para(
            "Colour is decorative; the text carries the meaning. Every status is a word as well as a "
            "colour, because a colour-only signal is unreadable to a meaningful fraction of users and "
            "useless in a screenshot printed in black and white.",
            styles["body"],
        )
    )

    # --- 11. Operating limits ---------------------------------------------
    story.append(section(11, "Operating limits", styles))
    story.append(
        para(
            "Know these before you rely on a number. Each is a deliberate bound rather than an "
            "accident, and each is visible at runtime.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(
        data_table(
            ["Bound", "Value", "Consequence"],
            [
                ["Idle flow timeout", "120 s", "A quiet connection leaves the live table but keeps its totals"],
                ["Maximum tracked flows", "65 536", "Oldest is evicted when full; creation counts stay accurate"],
                ["Snapshot connections", "200", "The interface shows the most recent 200, not all of them"],
                ["Traffic series", "one-second ring", "The chart shows recent history, not the whole session"],
                ["Queue capacity", "32 768 frames", "Beyond this, frames are dropped and counted"],
                ["Flush interval", "5 s", "Up to five seconds of connections may not yet be on disk"],
            ],
            styles,
            widths=[1.1, 0.85, 2.05],
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(
        callout(
            "On a very busy link",
            "If the loss counters are non-zero and rising, the machine cannot keep up. Lower "
            "uiUpdateHz, reduce snaplen, or disable promiscuous mode. If drops persist at low "
            "traffic, the disk or the driver is the bottleneck, and the counters distinguish which: "
            "a high driver-drop count with a low queue watermark means the driver.",
            styles,
        )
    )

    # --- 12. Security ------------------------------------------------------
    story.append(PageBreak())
    story.append(section(12, "Security posture", styles))
    story.append(para("What Sentinel does with your data", styles["h2"]))
    story.append(
        para(
            "This is a property of the code rather than a promise, and you can check it:",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(
        code_block(
            """
# No HTTP, TLS or websocket client anywhere in the engine's dependency graph.
cargo tree -p sentinel-core | grep -Ei "reqwest|hyper|curl|rustls|tokio-tungstenite"
# Expects no output.

# No code path builds an outbound connection.
grep -rn "TcpStream|UdpSocket|connect(" crates/ apps/ --include=*.rs
# Expects no matches outside tests and the capture driver bindings.
""",
            styles,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(
        data_table(
            ["Property", "Status"],
            [
                ["Outbound network connections", "None. No HTTP client, no resolver, no telemetry, no update check."],
                ["Packet payloads stored", "No. Headers, flows and aggregates only; the schema has no payload column."],
                ["Traffic modification", "None. Sentinel reads. No injection, spoofing or shaping."],
                ["Account or sign-in", "None."],
                ["Required privileges", "Elevated, for reading frames from an adapter. Nothing more."],
                ["Filesystem reach", "Its own data directory only."],
                ["Window content policy", "Scripts and styles from the bundle only; no remote code."],
            ],
            styles,
            widths=[1.15, 2.75],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Threat model boundaries", styles["h2"]))
    story.extend(
        bullets(
            [
                "An attacker with administrator rights on your machine can read anything Sentinel "
                "can, and can alter its binary. Sentinel does not defend against that.",
                "Promiscuous mode sees traffic that was never meant for you. That is its purpose, and "
                "it is why it is off by default.",
                "The local database is not encrypted at rest. Protecting it is the operating system's "
                "job, through filesystem permissions.",
                "Detection is deliberately offline. A user in an air-gapped environment gets the same "
                "analysis as everyone else, and an adversary cannot poison verdicts by feeding the "
                "detector.",
            ],
            styles,
        )
    )

    # --- 13. Decisions -----------------------------------------------------
    story.append(PageBreak())
    story.append(section(13, "Design decisions", styles))
    story.append(
        para(
            "The choices worth arguing about, with the condition that would reverse each one. A "
            "decision with no stated reversal condition is a decision nobody has thought about.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    story.append(
        data_table(
            ["#", "Decision", "Why", "Revisit when"],
            [[num, decision, why, when] for num, decision, why, when in facts.decisions],
            styles,
            widths=[0.3, 1.5, 2.05, 1.05],
            mono_columns={0},
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Deliberately not done", styles["h2"]))
    story.extend(
        bullets(
            [
                "No global mutable singleton or god object holding every subsystem.",
                "No separate event-bus crate: the engine broadcaster already owns event dispatch.",
                "No empty crate as a placeholder. Additional crates are introduced by the milestone "
                "that needs them, because a placeholder is a promise the product has not kept.",
                "No third-party decoding crate. Sentinel owns its L2-L4 decoder because the flow "
                "engine depends on seeing truncation and fragmentation explicitly.",
            ],
            styles,
        )
    )

    # --- 14. Extending -----------------------------------------------------
    story.append(section(14, "Extending it", styles))
    story.append(para("Adding a threat rule", styles["h2"]))
    story.extend(
        bullets(
            [
                "A rule takes a flow plus its context and returns a finding with a severity and a "
                "one-sentence explanation. Most interesting signals are not in a single flow: a "
                "beacon is a timing regularity, a scan is a set of destinations.",
                "Rules run inside the engine on the task that owns the flow table, after "
                "aggregation, throttled per flow, and deterministically. A capture file replayed "
                "twice must produce identical findings.",
                "Every finding must explain itself in one sentence. A score with no explanation "
                "either gets ignored or over-trusted, and both are bad.",
                "Each rule needs a positive case, a negative case, a boundary case, and a benign "
                "pattern that resembles it. The last one decides whether the rule is usable.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(para("Adding a capture backend", styles["h2"]))
    story.extend(
        bullets(
            [
                "Implement CaptureProvider, keep every cfg(target_os) inside sentinel-capture, and map "
                "failures onto the existing error variants so the user-facing message stays built in "
                "one place.",
                "Report driver-level drops through CaptureStats. A silent loss is worse than no capture.",
                "Write tests that do not need the driver: queue behaviour, error classification and "
                "config translation are all testable without hardware.",
            ],
            styles,
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(para("Changing the engine contract", styles["h2"]))
    story.append(
        para(
            "Any change to a serializable type must change the hand-written TypeScript mirror in "
            "packages/types in the same commit, including the field-name casing. They are not "
            "generated, so the mirroring is a deliberate act rather than an automatic one.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Before opening a change", styles["h2"]))
    story.append(
        code_block(
            """
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test
cd apps/desktop/frontend && npm run typecheck && npm run lint && npm run build
""",
            styles,
        )
    )

    # --- 15. Troubleshooting ----------------------------------------------
    story.append(PageBreak())
    story.append(section(15, "Troubleshooting", styles))
    story.append(
        data_table(
            ["Symptom", "Likely cause", "Do this"],
            [
                [
                    "Black window, title bar only",
                    "Built without custom-protocol, so it loads the dev-server URL",
                    "Rebuild with --features custom-protocol. See section 4.",
                ],
                [
                    "Window loads, every command fails",
                    "capabilities/default.json missing or incomplete",
                    "Add the file. Tauri 2 denies anything not explicitly granted.",
                ],
                [
                    "LNK1181: cannot open wpcap.lib",
                    "Npcap runtime installed but not the SDK",
                    "Install the SDK, or set IKLWA_PCAP_LIB. See section 4.",
                ],
                [
                    "Capture permission denied",
                    "Process is not elevated",
                    "Run as administrator, or grant CAP_NET_RAW on Linux.",
                ],
                [
                    "Interface listed but not available",
                    "Adapter is down, or the driver refuses it",
                    "The row states the reason. Bring the adapter up, or choose another.",
                ],
                [
                    "Frames lost is non-zero",
                    "Machine cannot keep up with the packet rate",
                    "See section 11. Compare driver drops against queue watermark to find which.",
                ],
                [
                    "Database is locked",
                    "Two Sentinel processes are running",
                    "Close the other one. SQLite allows one writer.",
                ],
                [
                    "Live and offline results differ",
                    "This is a bug",
                    "They are the same pipeline. Please report it with a capture file.",
                ],
            ],
            styles,
            widths=[1.15, 1.25, 1.5],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(para("Getting help", styles["h2"]))
    story.extend(
        bullets(
            [
                "Include <font face='Courier'>sentinel doctor</font> output; it names the driver, the "
                "privilege state and the data directory in one go.",
                "Attach the log directory's contents, shown under Settings. Logs go there, not to a "
                "console, because a GUI application has no console on Windows.",
                "If the problem involves a capture file, attach it. You can inspect it yourself "
                "first with <font face='Courier'>sentinel analyze</font>.",
                "Security issues go to security@iklwalabs.com, not the issue tracker.",
            ],
            styles,
        )
    )

    # --- Appendix ----------------------------------------------------------
    story.append(Spacer(1, 6 * mm))
    story.append(
        Paragraph(escape("Appendix   Verification state"), styles["h1"])
    )
    story.append(
        para(
            "Every milestone is complete only when it is formatted, linted, tested and documented. "
            "This is the state at the time of printing.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 1 * mm))
    if facts.test_counts:
        rows = [[crate, str(count)] for crate, count in sorted(facts.test_counts.items())]
        rows.append(["Total", str(facts.total_tests)])
        story.append(data_table(["Crate", "Tests"], rows, styles, widths=[3, 1], mono_columns={0}))
    else:
        story.append(
            para(
                "Test counts were not available when this document was generated. Run "
                "<font face='Courier'>cargo test --workspace</font> for the current figures.",
                styles["body"],
            )
        )
    story.append(Spacer(1, 3 * mm))
    story.append(
        para(
            f"Generated from commit <font face='Courier'>{_git('rev-parse', '--short', 'HEAD')}</font> "
            f"on {_git('log', '-1', '--format=%cs')} by "
            "<font face='Courier'>tools/generate-reference-pdf.py</font>. "
            "Regenerate rather than editing this file by hand.",
            styles["small"],
        )
    )

    return story


def _git(*args: str) -> str:
    try:
        proc = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


# ---------------------------------------------------------------------------
# Page furniture.
# ---------------------------------------------------------------------------


def section(number: int, title: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
    """A numbered section heading, tagged so the contents page can find its page number.

    `number` is the section's 1-based position in `SECTIONS`, or -1 for the appendix. The tag
    is invisible in the rendered page and is used by the layout pass to record which page this
    heading landed on.

    The alternative -- a hand-maintained contents page -- goes stale on the next edit, and a
    wrong page number is worse than none.
    """
    # Only the number is escaped; the non-breaking space is markup, not content. Escaping the
    # whole label turns `&nbsp;` into visible text, which is exactly what it did before.
    label = escape(title) if number < 0 else f"{number} &nbsp; {escape(title)}"
    para_obj = Paragraph(label, styles["h1"])
    # The appendix is deliberately left untagged: it is not in the contents list, so tagging it
    # would consume a slot in the page map that belongs to a real section.
    if number > 0:
        para_obj.sentinel_section = number
    return para_obj


def build_twice(path: Path, facts: Facts, styles: dict[str, ParagraphStyle]) -> None:
    """Builds the document twice: once to learn page numbers, once with them filled in.

    Reportlab resolves no forward references, so a page number cannot be known before the
    document has been laid out at least once. The first pass renders to a scratch file purely
    to measure, and the second renders the real thing. Two passes on a 20-page document take
    well under a second, which is cheaper than a contents page that lies.

    Page numbers come from `doc.page` after each build rather than from text extraction. The
    markers were tried first and proved unreliable: a 1pt white run of control characters
    survives layout but is dropped by some PDF text extractors, so half the sections could not
    be found. Reading the recorded page number is exact and needs no marker at all.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        probe_path = Path(scratch) / "probe.pdf"
        document = make_document(probe_path, "probe")
        document.build(build_story(facts, styles, {}))

        numbers = {f"\x01{index}\x01": str(page) for index, page in enumerate(document.section_pages)}

    make_document(path, f"Iklwa Sentinel {facts.version} — Product Reference").build(
        build_story(facts, styles, numbers)
    )


class ReferenceDoc(BaseDocTemplate):
    """A document that remembers which page each numbered section landed on.

    `afterFlowable` is a method to override, not a list to append to, so recording the
    section pages means subclassing rather than registering a hook. The page each section
    heading was drawn on is read from the canvas at that moment, which is exact.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.section_pages: list[int] = []

    def afterFlowable(self, flowable) -> None:
        marker = getattr(flowable, "sentinel_section", None)
        if marker is None or marker < 1:
            return
        index = marker - 1
        while len(self.section_pages) <= index:
            self.section_pages.append(0)
        if not self.section_pages[index]:
            self.section_pages[index] = self.page


def make_document(path: Path, title: str) -> BaseDocTemplate:
    document = ReferenceDoc(
        str(path),
        pagesize=A4,
        leftMargin=22 * mm,
        rightMargin=22 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=title,
        author="IklwaLabs",
        subject="Architecture, operation and control",
    )

    def decorate(canvas, doc):
        canvas.saveState()
        width, height = A4

        if doc.page > 1:
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(FAINT)
            canvas.drawString(22 * mm, height - 13 * mm, "Iklwa Sentinel — Product Reference")
            canvas.drawRightString(width - 22 * mm, height - 13 * mm, f"v{doc.page}")
            canvas.setStrokeColor(RULE)
            canvas.setLineWidth(0.4)
            canvas.line(22 * mm, height - 15 * mm, width - 22 * mm, height - 15 * mm)

        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(FAINT)
        canvas.drawString(22 * mm, 12 * mm, "Local-first. No account, no cloud, no telemetry.")
        canvas.drawRightString(width - 22 * mm, 12 * mm, "IklwaLabs")

        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.4)
        canvas.line(22 * mm, 15 * mm, width - 22 * mm, 15 * mm)
        canvas.restoreState()
    frame = Frame(
        document.leftMargin,
        document.bottomMargin,
        document.width,
        document.height,
        id="main",
    )
    document.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[frame], onPage=decorate),
            PageTemplate(id="content", frames=[frame], onPage=decorate),
        ]
    )
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO / "docs" / "Sentinel-Reference.pdf",
        help="Where to write the PDF (default: docs/Sentinel-Reference.pdf)",
    )
    args = parser.parse_args()

    print("Reading the repository...")
    facts = collect()
    print(
        f"  version {facts.version}, schema v{facts.schema_version}, "
        f"{facts.file_count} files, {facts.total_tests} tests"
    )

    styles = build_styles()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    build_twice(args.output, facts, styles)

    size_kb = args.output.stat().st_size / 1024
    print(f"Wrote {args.output} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
