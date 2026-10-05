/**
 * The interface picker.
 *
 * First run lands here, and so does any change of interface. Each row states the facts a
 * person needs to choose: what the adapter is, what addresses it holds, and whether capture is
 * possible right now. An interface Sentinel cannot open is shown with the reason rather than
 * hidden, because "why is my Wi-Fi missing" is the most common first-run question.
 */

import { useMemo } from 'react';
import { formatAddresses, type NetworkInterface } from '@sentinel/types';
import { Badge, Button, Dot, EmptyState } from '@/components/ui';

function kindLabel(iface: NetworkInterface): string {
  if (iface.isLoopback) return 'Loopback';
  switch (iface.kind) {
    case 'wireless':
      return 'Wireless';
    case 'ethernet':
      return 'Wired';
    case 'tunnel':
      return 'Tunnel';
    case 'virtual':
      return 'Virtual';
    default:
      return 'Other';
  }
}

/** Suggests an interface, without deciding for the user. */
function suggested(interfaces: NetworkInterface[]): NetworkInterface | null {
  const usable = interfaces.filter((iface) => iface.captureReady);
  return (
    usable.find((iface) => !iface.isLoopback && iface.isVirtual === false && iface.addresses.length > 0) ??
    usable.find((iface) => !iface.isLoopback) ??
    usable[0] ??
    null
  );
}

export function InterfacePicker({
  open,
  interfaces,
  busy,
  onSelect,
  onClose,
}: {
  open: boolean;
  interfaces: NetworkInterface[];
  busy: boolean;
  onSelect: (interfaceId: string) => void;
  onClose: () => void;
}) {
  const recommended = useRecommended(interfaces);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-6" role="dialog" aria-modal="true" aria-label="Choose a network interface">
      <div className="flex max-h-[80vh] w-full max-w-2xl flex-col overflow-hidden rounded-lg border border-[var(--border-default)] bg-[var(--surface-raised)] shadow-[var(--shadow-overlay)]">
        <header className="flex items-center justify-between border-b border-[var(--border-subtle)] px-4 py-3">
          <div>
            <h2 className="text-[13px] font-medium text-[var(--text-primary)]">Choose a network interface</h2>
            <p className="mt-0.5 text-[12px] text-[var(--text-muted)]">
              Sentinel needs permission to read packets from the adapter you select.
            </p>
          </div>
          <Button variant="ghost" onClick={onClose} title="Close">
            Close
          </Button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {interfaces.length === 0 ? (
            <EmptyState
              title="No interfaces were found"
              body="Sentinel could not enumerate your network adapters. Check that at least one is connected, then try again."
            />
          ) : (
            <ul className="divide-y divide-[var(--border-subtle)]">
              {interfaces.map((iface) => (
                <li key={iface.id}>
                  <button
                    type="button"
                    disabled={!iface.captureReady || busy}
                    onClick={() => onSelect(iface.id)}
                    className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left transition-colors hover:bg-[var(--surface-overlay)] disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:bg-transparent"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-[13px] font-medium text-[var(--text-primary)]">{iface.name}</span>
                        <Badge tone="neutral">{kindLabel(iface)}</Badge>
                        {recommended?.id === iface.id ? <Badge tone="accent">Recommended</Badge> : null}
                      </div>

                      <p className="mono mt-0.5 truncate text-[12px] text-[var(--text-muted)]">
                        {formatAddresses(iface.addresses)}
                      </p>

                      {iface.description && iface.description !== iface.name ? (
                        <p className="truncate text-[11px] text-[var(--text-faint)]">{iface.description}</p>
                      ) : null}

                      {!iface.captureReady ? (
                        <p className="mt-1 text-[12px] text-[var(--severity-medium)]">
                          {iface.captureBlockedReason ?? 'This interface cannot be monitored right now.'}
                        </p>
                      ) : null}
                    </div>

                    <div className="flex shrink-0 items-center gap-2">
                      {iface.captureReady ? <Dot tone="safe" /> : <Dot tone="warning" />}
                      <span className="text-[12px] text-[var(--text-secondary)]">
                        {iface.captureReady ? 'Ready' : 'Unavailable'}
                      </span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <footer className="flex items-center justify-between gap-3 border-t border-[var(--border-subtle)] px-4 py-2.5">
          <p className="text-[11px] text-[var(--text-faint)]">
            Monitoring reads traffic only. Sentinel does not modify anything on your network.
          </p>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </footer>
      </div>
    </div>
  );
}

/** Recomputes the suggested interface whenever the list changes. */
function useRecommended(interfaces: NetworkInterface[]): NetworkInterface | null {
  return useMemo(() => suggested(interfaces), [interfaces]);
}
