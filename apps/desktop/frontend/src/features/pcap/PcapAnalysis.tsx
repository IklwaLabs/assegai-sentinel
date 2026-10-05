/**
 * PCAP analysis view.
 *
 * The path field exists because a desktop webview cannot open a native file dialog without a
 * plugin, and v0.1 does not take a dependency on one. The user types or pastes a path; the same
 * engine path is used, so the result is identical to live monitoring.
 */

import { useState } from 'react';
import type { EngineSnapshot } from '@sentinel/types';
import { Button, EmptyState, Field, Panel } from '@/components/ui';
import { bytes, count } from '@/lib/format';

export function PcapAnalysis({
  snapshot,
  busy,
  onAnalyze,
  onOpenConnections,
}: {
  snapshot: EngineSnapshot | null;
  busy: boolean;
  onAnalyze: (path: string) => void;
  onOpenConnections: () => void;
}) {
  const [path, setPath] = useState('');
  const analyzing = snapshot?.state.state === 'analyzing';

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-[15px] font-medium text-[var(--text-primary)]">PCAP analysis</h1>
        <p className="mt-0.5 max-w-2xl text-[12px] text-[var(--text-muted)] text-balance">
          Analyse a saved capture with the same decoder, flow engine and rules that run during
          live monitoring. Nothing is uploaded; the file is read in place.
        </p>
      </div>

      <Panel title="Capture file">
        <div className="px-4 py-3">
          <Field
            label="Path to a PCAP file"
            hint="Classic PCAP is read directly. Convert PCAPNG with: editcap -F pcap in.pcapng out.pcap"
          >
            <div className="flex items-center gap-2">
              <input
                value={path}
                onChange={(event) => setPath(event.target.value)}
                placeholder="C:\captures\session.pcap"
                aria-label="Path to a PCAP file"
                className="mono min-w-0 flex-1 rounded-md border border-[var(--border-default)] bg-[var(--surface-input)] px-2.5 py-1.5 text-[13px] text-[var(--text-primary)] placeholder:text-[var(--text-faint)]"
              />
              <Button variant="primary" disabled={busy || path.trim().length === 0 || analyzing} onClick={() => onAnalyze(path.trim())}>
                {analyzing ? 'Analysing…' : 'Analyse'}
              </Button>
            </div>
          </Field>
        </div>
      </Panel>

      {analyzing ? (
        <Panel title="In progress">
          <EmptyState
            title="Analysing the capture"
            body="Sentinel is decoding the file. This happens on the same engine that runs live monitoring, so the results match."
          />
        </Panel>
      ) : snapshot && snapshot.state.state === 'idle' && snapshot.totalPackets > 0 ? (
        <Panel
          title="Last analysis"
          actions={
            <Button variant="ghost" onClick={onOpenConnections}>
              View connections
            </Button>
          }
        >
          <div className="grid grid-cols-2 gap-4 px-4 py-4 sm:grid-cols-4">
            <Summary label="Packets" value={count(snapshot.totalPackets)} />
            <Summary label="Connections" value={count(snapshot.connections.length)} />
            <Summary label="Uploaded" value={bytes(snapshot.totalUploadBytes)} />
            <Summary label="Downloaded" value={bytes(snapshot.totalDownloadBytes)} />
          </div>
        </Panel>
      ) : (
        <Panel title="Analysis">
          <EmptyState
            title="No capture analysed yet"
            body="Choose a PCAP file above. Sentinel reports endpoints, protocols, connections and anything suspicious it finds."
          />
        </Panel>
      )}
    </div>
  );
}

function Summary({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="label">{label}</span>
      <span className="mono text-[14px] text-[var(--text-primary)]">{value}</span>
    </div>
  );
}
