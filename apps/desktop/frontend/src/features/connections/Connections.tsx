/**
 * The connections table.
 *
 * A performance-first view: the engine sends a bounded, pre-sorted list of connections and
 * this renders it. Search and sorting operate on that list, which is why they are honest about
 * being filters rather than pretending to query the whole history.
 *
 * Clicking a row opens a side panel rather than navigating away, so a person comparing two
 * connections never loses their place.
 */

import { useMemo, useState } from 'react';
import type { ConnectionRow, EngineSnapshot } from '@sentinel/types';
import { Badge, Button, Dot, EmptyState, Panel } from '@/components/ui';
import { bytes, clockTime, count, duration, endpoint } from '@/lib/format';

type SortKey = 'recent' | 'volume' | 'upload' | 'name';

const SORTS: { key: SortKey; label: string }[] = [
  { key: 'recent', label: 'Recent' },
  { key: 'volume', label: 'Total' },
  { key: 'upload', label: 'Upload' },
  { key: 'name', label: 'Destination' },
];

export function Connections({ snapshot, paused, onTogglePause }: { snapshot: EngineSnapshot; paused: boolean; onTogglePause: () => void }) {
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<SortKey>('recent');
  const [selected, setSelected] = useState<ConnectionRow | null>(null);

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const filtered = needle
      ? snapshot.connections.filter((row) =>
          [row.source, row.destination, row.service, row.domain, row.process, row.protocol]
            .filter((value): value is string => Boolean(value))
            .some((value) => value.toLowerCase().includes(needle)),
        )
      : snapshot.connections;

    return [...filtered].sort((a, b) => {
      switch (sort) {
        case 'volume':
          return b.uploadBytes + b.downloadBytes - (a.uploadBytes + a.downloadBytes);
        case 'upload':
          return b.uploadBytes - a.uploadBytes;
        case 'name':
          return a.destination.localeCompare(b.destination);
        case 'recent':
        default:
          return b.lastSeenUs - a.lastSeenUs;
      }
    });
  }, [search, snapshot.connections, sort]);

  const filtered = rows.length !== snapshot.connections.length;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Filter by address, service or application"
          aria-label="Filter connections"
          className="mono min-w-64 flex-1 rounded-md border border-[var(--border-default)] bg-[var(--surface-input)] px-2.5 py-1.5 text-[13px] text-[var(--text-primary)] placeholder:text-[var(--text-faint)]"
        />

        <div className="flex items-center gap-1">
          {SORTS.map((option) => (
            <button
              key={option.key}
              type="button"
              onClick={() => setSort(option.key)}
              aria-pressed={sort === option.key}
              className={`rounded-md px-2 py-1 text-[12px] transition-colors ${
                sort === option.key
                  ? 'bg-[var(--surface-overlay)] text-[var(--text-primary)]'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>

        <Button variant={paused ? 'secondary' : 'ghost'} onClick={onTogglePause} title="Freeze the list while you read it">
          {paused ? 'Resume' : 'Pause'}
        </Button>
      </div>

      {paused ? (
        <p className="flex items-center gap-2 text-[12px] text-[var(--text-muted)]">
          <Dot tone="warning" />
          Paused. New connections are still being recorded and will appear when you resume.
        </p>
      ) : null}

      <Panel
        className="min-h-0 flex-1 overflow-hidden"
        title={`Connections${filtered ? ` (${rows.length} of ${snapshot.connections.length})` : ''}`}
      >
        {snapshot.connections.length === 0 ? (
          <EmptyState
            title="No connections yet"
            body="Sentinel shows connections as it observes them. Start monitoring on a network interface, or analyse a capture file, to populate this list."
          />
        ) : rows.length === 0 ? (
          <EmptyState title="Nothing matched that filter" body="No connection matches the current search. Clear it to see everything again." />
        ) : (
          <div className="min-h-0 overflow-auto">
            <table className="w-full border-collapse text-[13px]">
              <thead className="sticky top-0 z-10 bg-[var(--surface-raised)]">
                <tr className="border-b border-[var(--border-subtle)] text-left">
                  <Th className="w-40">Application</Th>
                  <Th>Destination</Th>
                  <Th className="w-16">Proto</Th>
                  <Th numeric>Upload</Th>
                  <Th numeric>Download</Th>
                  <Th numeric className="w-16">Packets</Th>
                  <Th numeric className="w-20">Duration</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelected(row)}
                    className={`cursor-pointer border-b border-[var(--border-subtle)] transition-colors hover:bg-[var(--surface-overlay)] ${
                      selected?.id === row.id ? 'bg-[var(--surface-overlay)]' : ''
                    }`}
                  >
                    <td className="px-3 py-2">
                      <span className="block truncate text-[var(--text-primary)]">{row.process ?? '—'}</span>
                      <span className="mono block truncate text-[11px] text-[var(--text-faint)]">{label(row)}</span>
                    </td>

                    <td className="px-3 py-2">
                      <span className="mono block truncate text-[var(--text-primary)]">{row.destination}</span>
                      {row.service || row.domain ? (
                        <span className="block truncate text-[11px] text-[var(--text-muted)]">{row.service ?? row.domain}</span>
                      ) : null}
                    </td>

                    <td className="px-3 py-2">
                      <Badge tone="neutral">{row.protocol}</Badge>
                    </td>

                    <Td numeric>{bytes(row.uploadBytes)}</Td>
                    <Td numeric>{bytes(row.downloadBytes)}</Td>
                    <Td numeric>{count(row.packets)}</Td>
                    <Td numeric className="text-[var(--text-muted)]">
                      {duration(row.lastSeenUs - row.firstSeenUs)}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selected ? <ConnectionDetail row={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

/** A table header cell. */
function Th({ children, numeric = false, className = '' }: { children: React.ReactNode; numeric?: boolean; className?: string }) {
  return (
    <th scope="col" className={`px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)] ${numeric ? 'text-right' : ''} ${className}`}>
      {children}
    </th>
  );
}

/** A numeric table cell, right-aligned so digits line up. */
function Td({ children, numeric = false, className = '' }: { children: React.ReactNode; numeric?: boolean; className?: string }) {
  return <td className={`mono px-3 py-2 ${numeric ? 'text-right' : ''} ${className}`}>{children}</td>;
}

/** The best available name for a connection: application, service, then domain. */
function label(row: ConnectionRow): string {
  return row.service ?? row.domain ?? row.source;
}

/**
 * The connection detail panel.
 *
 * Information is grouped by what a person is looking for: what is this, where did it go, how
 * much did it move, and is anything unusual. Nothing is dumped as raw JSON.
 */
function ConnectionDetail({ row, onClose }: { row: ConnectionRow; onClose: () => void }) {
  const remote = endpoint(row.destination);
  const local = row.local ? endpoint(row.local) : null;

  return (
    <aside className="fixed right-0 top-0 z-40 flex h-full w-[380px] flex-col border-l border-[var(--border-default)] bg-[var(--surface-raised)] shadow-[var(--shadow-overlay)]">
      <header className="flex items-start justify-between gap-3 border-b border-[var(--border-subtle)] px-4 py-3">
        <div className="min-w-0">
          <h2 className="truncate text-[13px] font-medium text-[var(--text-primary)]">{label(row)}</h2>
          <p className="mono mt-0.5 truncate text-[11px] text-[var(--text-muted)]">{remote.address}</p>
        </div>
        <Button variant="ghost" onClick={onClose} title="Close details">
          Close
        </Button>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-4">
        <Section title="Connection">
          <Row label="Remote" value={`${remote.address}${remote.port ? `:${remote.port}` : ''}`} />
          <Row label="Local" value={local ? `${local.address}${local.port ? `:${local.port}` : ''}` : 'Not on this machine'} />
          <Row label="Protocol" value={`${row.protocol} ${row.state.toLowerCase()}`} />
          <Row label="Started" value={clockTime(row.firstSeenUs)} />
          <Row label="Last seen" value={clockTime(row.lastSeenUs)} />
          <Row label="Duration" value={duration(row.lastSeenUs - row.firstSeenUs)} />
        </Section>

        <Section title="Traffic">
          <Row label="Upload" value={bytes(row.uploadBytes)} />
          <Row label="Download" value={bytes(row.downloadBytes)} />
          <Row label="Total" value={bytes(row.uploadBytes + row.downloadBytes)} />
          <Row label="Packets" value={count(row.packets)} />
        </Section>

        <Section title="Application">
          <Row label="Process" value={row.process ?? 'Not resolved on this system'} />
        </Section>

        <Section title="Risk">
          {/* Risk scoring arrives with the security milestone. Until then the panel says so
              rather than showing a zero that would read as "safe". */}
          <Row
            label="Score"
            value={
              row.riskScore === null
                ? 'Not yet assessed'
                : `${row.riskScore} / 100${row.alertCount > 0 ? ` · ${row.alertCount} alerts` : ''}`
            }
          />
        </Section>
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
