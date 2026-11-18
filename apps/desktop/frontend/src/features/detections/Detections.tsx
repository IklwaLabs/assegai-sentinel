/**
 * Detections: what the engine decided was worth reporting.
 *
 * The engine sends a bounded, pre-sorted list and this view renders it. Ordering is the
 * engine's, so the desktop app, the CLI and an export cannot disagree about which finding is
 * most important.
 *
 * Severity and confidence are shown as separate facts. Collapsing them into one score would
 * imply a certainty the detector does not have: a large upload can be high severity and medium
 * confidence, and the operator needs to see both to decide what to do.
 */

import { useMemo, useState } from 'react';
import type { Confidence, EngineSnapshot, Finding, Severity } from '@sentinel/types';
import { Badge, Button, EmptyState, Panel } from '@/components/ui';
import { clockTime, count, duration } from '@/lib/format';

/** Severity ordered most serious first, which is also the order the engine uses. */
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_TONE: Record<Severity, 'critical' | 'warning' | 'info' | 'neutral'> = {
  critical: 'critical',
  high: 'warning',
  medium: 'info',
  low: 'neutral',
  info: 'neutral',
};

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
};

const KIND_LABEL: Record<Finding['kind'], string> = {
  arpSpoofing: 'ARP spoofing',
  portScan: 'Port scan',
  hostSweep: 'Host sweep',
  tcpFlagAnomaly: 'TCP flag anomaly',
  cleartextProtocol: 'Cleartext protocol',
  possibleBeaconing: 'Possible beaconing',
  largeOutboundTransfer: 'Large outbound transfer',
};

export function Detections({ snapshot }: { snapshot: EngineSnapshot }) {
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const findings = snapshot.findings;
  const rows = useMemo(
    () => (severity === 'all' ? findings : findings.filter((finding) => finding.severity === severity)),
    [findings, severity],
  );

  // The selected finding is looked up from the list rather than stored, so it keeps updating
  // as the engine folds further observations into the same finding.
  const selected = findings.find((finding) => finding.id === selectedId) ?? null;

  const counts = useMemo(() => {
    const tally = new Map<Severity, number>();
    for (const finding of findings) {
      tally.set(finding.severity, (tally.get(finding.severity) ?? 0) + 1);
    }
    return tally;
  }, [findings]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <div className="flex flex-wrap items-center gap-1">
        <FilterChip active={severity === 'all'} onClick={() => setSeverity('all')} label="All" count={findings.length} />
        {SEVERITIES.map((option) => (
          <FilterChip
            key={option}
            active={severity === option}
            onClick={() => setSeverity(option)}
            label={option[0]!.toUpperCase() + option.slice(1)}
            count={counts.get(option) ?? 0}
          />
        ))}
      </div>

      {/* An incomplete list is stated, never hidden. A capped list presented as complete is
          how a serious finding gets overlooked. */}
      {snapshot.findingsSuppressed > 0 ? (
        <p className="text-[12px] text-[var(--severity-medium)]">
          {count(snapshot.findingsSuppressed)} further findings were discarded because the session
          held more than the engine keeps in memory. Restart monitoring to begin a fresh list.
        </p>
      ) : null}
      {snapshot.findingsTotal > findings.length ? (
        <p className="text-[12px] text-[var(--text-muted)]">
          Showing the {count(findings.length)} most severe of {count(snapshot.findingsTotal)}{' '}
          detections. The rest are stored; run <span className="mono">sentinel findings</span> to read them.
        </p>
      ) : null}

      <Panel className="min-h-0 flex-1 overflow-hidden" title={`Detections${severity === 'all' ? '' : ` (${rows.length} of ${findings.length})`}`}>
        {findings.length === 0 ? (
          <EmptyState
            title="Nothing detected"
            body="Sentinel reports a behaviour only after it crosses a threshold. Start monitoring on an interface, or analyse a capture file, and detections will appear here. An empty list means nothing crossed a threshold, not that the network is certified clean."
          />
        ) : rows.length === 0 ? (
          <EmptyState title="No findings at this severity" body="Choose another severity, or show everything." />
        ) : (
          <div className="min-h-0 overflow-auto">
            <table className="w-full border-collapse text-[13px]">
              <thead className="sticky top-0 z-10 bg-[var(--surface-raised)]">
                <tr className="border-b border-[var(--border-subtle)] text-left">
                  <th scope="col" className="w-24 px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                    Severity
                  </th>
                  <th scope="col" className="px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                    Finding
                  </th>
                  <th scope="col" className="w-28 px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                    Confidence
                  </th>
                  <th scope="col" className="w-20 px-3 py-2 text-right text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                    Seen
                  </th>
                  <th scope="col" className="w-32 px-3 py-2 text-right text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                    Last seen
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => setSelectedId(finding.id)}
                    className={`cursor-pointer border-b border-[var(--border-subtle)] transition-colors hover:bg-[var(--surface-overlay)] ${
                      selected?.id === finding.id ? 'bg-[var(--surface-overlay)]' : ''
                    }`}
                  >
                    <td className="px-3 py-2">
                      <Badge tone={SEVERITY_TONE[finding.severity]}>{capitalise(finding.severity)}</Badge>
                    </td>
                    <td className="px-3 py-2">
                      <span className="block truncate text-[var(--text-primary)]">{finding.title}</span>
                      <span className="mono block truncate text-[11px] text-[var(--text-faint)]">
                        {KIND_LABEL[finding.kind]}
                        {finding.source ? ` · ${finding.source}` : ''}
                        {finding.destination ? ` → ${finding.destination}` : ''}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-[12px] text-[var(--text-muted)]">{CONFIDENCE_LABEL[finding.confidence]}</td>
                    <td className="mono px-3 py-2 text-right text-[var(--text-secondary)]">{count(finding.occurrences)}</td>
                    <td className="mono px-3 py-2 text-right text-[var(--text-muted)]">{clockTime(finding.lastSeenUs)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selected ? <FindingDetail finding={selected} onClose={() => setSelectedId(null)} /> : null}
    </div>
  );
}

/** One severity filter, showing its count so an empty bucket is obvious before clicking. */
function FilterChip({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded-md px-2 py-1 text-[12px] transition-colors ${
        active
          ? 'bg-[var(--surface-overlay)] text-[var(--text-primary)]'
          : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
      }`}
    >
      {label}
      <span className="mono ml-1.5 text-[11px] text-[var(--text-faint)]">{count}</span>
    </button>
  );
}

/**
 * The finding detail panel.
 *
 * Shows what was seen, the evidence behind it, and what to do, in that order. The advice is
 * the engine's, not the interface's, so a person reading the desktop app and the CLI gets the
 * same instructions.
 */
function FindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <aside className="fixed right-0 top-0 z-40 flex h-full w-[420px] flex-col border-l border-[var(--border-default)] bg-[var(--surface-raised)] shadow-[var(--shadow-overlay)]">
      <header className="flex items-start justify-between gap-3 border-b border-[var(--border-subtle)] px-4 py-3">
        <div className="min-w-0">
          <div className="mb-1 flex items-center gap-2">
            <Badge tone={SEVERITY_TONE[finding.severity]}>{capitalise(finding.severity)}</Badge>
            <span className="text-[11px] text-[var(--text-muted)]">{CONFIDENCE_LABEL[finding.confidence]}</span>
          </div>
          <h2 className="text-[13px] font-medium text-[var(--text-primary)]">{finding.title}</h2>
        </div>
        <Button variant="ghost" onClick={onClose} title="Close details">
          Close
        </Button>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-4">
        <section className="mb-5">
          <p className="label mb-1.5">What was seen</p>
          <p className="text-[12px] leading-relaxed text-[var(--text-secondary)]">{finding.detail}</p>
        </section>

        <Section title="Parties">
          <Row label="Source" value={finding.source ?? 'Not identifiable'} />
          <Row label="Destination" value={finding.destination ?? 'Not identifiable'} />
          <Row label="Kind" value={KIND_LABEL[finding.kind]} />
        </Section>

        <Section title="Timing">
          <Row label="First seen" value={clockTime(finding.firstSeenUs)} />
          <Row label="Last seen" value={clockTime(finding.lastSeenUs)} />
          <Row label="Span" value={duration(finding.lastSeenUs - finding.firstSeenUs)} />
          <Row label="Observations" value={count(finding.occurrences)} />
        </Section>

        {finding.evidence.length > 0 ? (
          <Section title="Evidence">
            {finding.evidence.map((item) => (
              <Row key={`${item.label}:${item.value}`} label={item.label} value={item.value} />
            ))}
          </Section>
        ) : null}

        {finding.advice.length > 0 ? (
          <section className="mb-5">
            <p className="label mb-1.5">What to do</p>
            <ol className="flex list-decimal flex-col gap-1.5 pl-4">
              {finding.advice.map((step) => (
                <li key={step} className="text-[12px] leading-relaxed text-[var(--text-secondary)]">
                  {step}
                </li>
              ))}
            </ol>
          </section>
        ) : null}
      </div>
    </aside>
  );
}

/** A labelled group inside the detail panel. */
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-5">
      <p className="label mb-1.5">{title}</p>
      <dl className="flex flex-col gap-1">{children}</dl>
    </section>
  );
}

/** One label/value pair. */
function Row({ label: name, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="shrink-0 text-[12px] text-[var(--text-muted)]">{name}</dt>
      <dd className="mono truncate text-right text-[12px] text-[var(--text-primary)]">{value}</dd>
    </div>
  );
}

function capitalise(value: string): string {
  return value.length === 0 ? value : value[0]!.toUpperCase() + value.slice(1);
}
