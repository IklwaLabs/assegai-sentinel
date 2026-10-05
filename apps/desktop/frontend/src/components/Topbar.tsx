/**
 * The top bar.
 *
 * Holds the three things a person needs to know without looking anywhere else: whether
 * monitoring is running, what it is attached to, and the control to change that.
 */

import { formatAddresses, type EngineSnapshot } from '@sentinel/types';
import { Button, Dot } from '@/components/ui';
import { stateLabel } from '@/stores/engine';

function tone(snapshot: EngineSnapshot | null): { dot: 'accent' | 'safe' | 'critical' | 'neutral'; text: string } {
  if (!snapshot) return { dot: 'neutral', text: 'Starting' };
  switch (snapshot.state.state) {
    case 'monitoring':
      return { dot: 'accent', text: stateLabel(snapshot) };
    case 'analyzing':
      return { dot: 'accent', text: stateLabel(snapshot) };
    case 'preparing':
      return { dot: 'neutral', text: 'Preparing' };
    case 'failed':
      return { dot: 'critical', text: 'Capture stopped' };
    default:
      return { dot: 'safe', text: 'Not monitoring' };
  }
}

export function Topbar({
  snapshot,
  busy,
  onToggleMonitoring,
  onOpenInterfacePicker,
}: {
  snapshot: EngineSnapshot | null;
  busy: boolean;
  onToggleMonitoring: () => void;
  onOpenInterfacePicker: () => void;
}) {
  const status = tone(snapshot);
  const active = snapshot?.state.state === 'monitoring';

  return (
    <header className="flex h-[var(--topbar-height)] shrink-0 items-center justify-between gap-4 border-b border-[var(--border-subtle)] bg-[var(--surface-raised)] px-4">
      <div className="flex min-w-0 items-center gap-2.5">
        <Dot tone={status.dot} />
        <span className="truncate text-[13px] text-[var(--text-primary)]">{status.text}</span>

        {snapshot?.interface ? (
          <span className="mono hidden truncate text-[12px] text-[var(--text-muted)] sm:inline">
            {formatAddresses(snapshot.interface.addresses)}
          </span>
        ) : null}
      </div>

      <div className="flex shrink-0 items-center gap-2">
        <Button variant="ghost" onClick={onOpenInterfacePicker} title="Choose the interface to monitor">
          Change interface
        </Button>
        <Button variant={active ? 'secondary' : 'primary'} onClick={onToggleMonitoring} disabled={busy}>
          {active ? 'Stop monitoring' : 'Start monitoring'}
        </Button>
      </div>
    </header>
  );
}
