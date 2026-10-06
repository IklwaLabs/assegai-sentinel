/**
 * The overview.
 *
 * Answers four questions in order, and nothing else:
 *   1. Is anything happening?      2. How much, and which way?
 *   3. Is anything wrong?           4. What changed recently?
 *
 * There is no grid of twelve metric tiles. The numbers read as a sentence, the chart is the
 * largest element because it is the only thing here that shows shape over time, and the
 * integrity notice appears only when there is something to say about data quality.
 */

import type { EngineSnapshot } from '@sentinel/types';
import { Badge, Button, EmptyState, Panel, Stat } from '@/components/ui';
import { TrafficChart } from '@/features/traffic/TrafficChart';
import { bytes, count, duration, rate } from '@/lib/format';
import { isActive } from '@/stores/engine';

export function Overview({
  snapshot,
  onStart,
  onOpenConnections,
}: {
  snapshot: EngineSnapshot | null;
  onStart: () => void;
  onOpenConnections: () => void;
}) {
  if (!snapshot) {
    return <div className="p-6 text-[13px] text-[var(--text-muted)]">Starting Sentinel…</div>;
  }

  const active = isActive(snapshot);
  const lost = snapshot.stats.queue.dropped + snapshot.metrics.backendDropped;
  const hasTraffic = snapshot.totalPackets > 0;

  return (
    <div className="flex flex-col gap-4">
      {/* 1 and 2: what is happening, and how much of it. */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-4 rounded-lg border border-[var(--border-default)] bg-[var(--surface-raised)] px-5 py-4 sm:grid-cols-3 lg:grid-cols-5">
        <Stat
          label="Download"
          value={rate(snapshot.downloadBps)}
          detail={active ? bytes(snapshot.totalDownloadBytes) : undefined}
          tone={active ? 'default' : 'muted'}
        />
        <Stat
          label="Upload"
          value={rate(snapshot.uploadBps)}
          detail={active ? bytes(snapshot.totalUploadBytes) : undefined}
          tone={active ? 'accent' : 'muted'}
        />
        <Stat label="Packets" value={count(snapshot.totalPackets)} />
        <Stat label="Connections" value={count(snapshot.connections.length)} />
        <Stat
          label="Session"
          value={hasTraffic ? duration(snapshot.lastSeenUs - snapshot.firstSeenUs) : '—'}
          detail={active ? undefined : 'not monitoring'}
          tone="muted"
        />
      </div>

      {/* Data quality, stated before any numbers are read as complete. */}
      {lost > 0 && (
        <div
          className="rail flex items-start justify-between gap-4 rounded-md border border-[var(--border-subtle)] bg-[var(--surface-raised)] py-2.5"
          style={{ borderLeftColor: 'var(--severity-medium)' }}
        >
          <div>
            <p className="text-[13px] text-[var(--text-primary)]">
              {count(lost)} {lost === 1 ? 'packet was' : 'packets were'} not recorded
            </p>
            <p className="mt-0.5 text-[12px] text-[var(--text-muted)]">
              Sentinel could not keep up, so the totals above are incomplete. A busy interface or a busy disk is the usual cause.
            </p>
          </div>
        </div>
      )}

      {/* 3 and 4: the shape of activity, then what is on the network now. */}
      <Panel
        title="Network activity"
        actions={
          hasTraffic ? (
            <Button variant="ghost" onClick={onOpenConnections}>
              View connections
            </Button>
          ) : null
        }
      >
        {active || hasTraffic ? (
          <TrafficChart points={snapshot.traffic} height={220} />
        ) : (
          <EmptyState
            title="No network activity yet"
            body="Start monitoring to see traffic as it happens. Sentinel will reconstruct connections and account for upload and download separately."
            action={
              <Button variant="primary" onClick={onStart}>
                Start monitoring
              </Button>
            }
          />
        )}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Busiest connections">
          {snapshot.connections.length === 0 ? (
            <EmptyState
              title="Nothing is connected yet"
              body="Once monitoring starts, the connections carrying the most data appear here."
            />
          ) : (
            <TopConnections snapshot={snapshot} limit={5} />
          )}
        </Panel>

        <Panel title="Protocols">
          {snapshot.totalPackets === 0 ? (
            <EmptyState title="No protocol data yet" body="Sentinel groups traffic by protocol once it has seen packets." />
          ) : (
            <ProtocolBreakdown snapshot={snapshot} />
          )}
        </Panel>
      </div>
    </div>
  );
}

/** The five busiest connections, as a quiet list rather than a table of eight columns. */
function TopConnections({ snapshot, limit }: { snapshot: EngineSnapshot; limit: number }) {
  const rows = [...snapshot.connections].sort((a, b) => total(b) - total(a)).slice(0, limit);

  return (
    <ul className="divide-y divide-[var(--border-subtle)]">
      {rows.map((row) => {
        const peak = Math.max(...rows.map(total), 1);
        return (
          <li key={row.id} className="flex items-center gap-3 px-4 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="mono truncate text-[12px] text-[var(--text-primary)]">
                  {row.service ?? row.domain ?? row.destination}
                </span>
                <Badge tone="neutral">{row.protocol}</Badge>
              </div>
              <span className="mono mt-0.5 block truncate text-[11px] text-[var(--text-faint)]">{row.destination}</span>
            </div>

            {/* A single bar carries the relative volume; the number carries the value. */}
            <div className="w-24 shrink-0">
              <div className="h-1 w-full overflow-hidden rounded-full bg-[var(--surface-overlay)]">
                <div
                  className="h-full rounded-full bg-[var(--accent)]"
                  style={{ width: `${Math.max(4, (total(row) / peak) * 100)}%` }}
                />
              </div>
            </div>

            <span className="mono w-16 shrink-0 text-right text-[12px] text-[var(--text-secondary)]">{bytes(total(row))}</span>
          </li>
        );
      })}
    </ul>
  );
}

/** Protocol mix, derived from what the engine already counted. */
function ProtocolBreakdown({ snapshot }: { snapshot: EngineSnapshot }) {
  const totals = new Map<string, number>();
  for (const row of snapshot.connections) {
    totals.set(row.protocol, (totals.get(row.protocol) ?? 0) + total(row));
  }

  const rows = [...totals.entries()].sort((a, b) => b[1] - a[1]);
  const grand = rows.reduce((sum, [, value]) => sum + value, 0) || 1;

  return (
    <ul className="flex flex-col gap-2.5 px-4 py-4">
      {rows.map(([protocol, value]) => (
        <li key={protocol} className="flex items-center gap-3">
          <span className="mono w-12 shrink-0 text-[12px] text-[var(--text-secondary)]">{protocol}</span>
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--surface-overlay)]">
            <div className="h-full rounded-full bg-[var(--text-muted)]" style={{ width: `${(value / grand) * 100}%` }} />
          </div>
          <span className="mono w-16 shrink-0 text-right text-[12px] text-[var(--text-muted)]">{bytes(value)}</span>
        </li>
      ))}
    </ul>
  );
}

/** Total bytes for a connection, used for ordering and bar widths. */
function total(row: EngineSnapshot['connections'][number]): number {
  return row.uploadBytes + row.downloadBytes;
}
