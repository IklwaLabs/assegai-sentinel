/**
 * The application shell.
 *
 * Owns layout and view switching, and nothing else. Every view receives the engine snapshot
 * and sends commands back; none of them hold independent state that could disagree with the
 * engine about what is happening.
 */

import { useEffect, useState } from 'react';
import { ErrorBanner } from '@/components/ErrorBanner';
import { Sidebar, type ViewId } from '@/components/Sidebar';
import { Topbar } from '@/components/Topbar';
import { Skeleton } from '@/components/ui';
import { Connections } from '@/features/connections/Connections';
import { InterfacePicker } from '@/features/interfaces/InterfacePicker';
import { Overview } from '@/features/overview/Overview';
import { PcapAnalysis } from '@/features/pcap/PcapAnalysis';
import { Settings } from '@/features/settings/Settings';
import { isActive, useEngine, type EngineStore } from '@/stores/engine';

export function App() {
  const store = useEngine();
  const [view, setView] = useState<ViewId>('overview');
  const [pickerOpen, setPickerOpen] = useState(false);

  // One initialisation for the life of the window: the engine subscription must not be
  // recreated when the view changes, or the renderer would receive two event streams.
  useEffect(() => {
    void store.initialize();
    void store.loadInterfaces();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The interface list and diagnostics are needed by the picker and Settings, and are cheap.
  useEffect(() => {
    if (view === 'settings') void store.loadDiagnostics();
  }, [view, store]);

  // First run: nothing is being monitored, so the picker is the most useful thing to show.
  const snapshot = store.snapshot;
  const hasStarted = snapshot !== null && snapshot.state.state !== 'idle';
  useEffect(() => {
    if (snapshot && !hasStarted && store.interfaces.length > 0 && view === 'overview') {
      setPickerOpen(true);
    }
  }, [hasStarted, snapshot, store.interfaces.length, view]);

  const active = isActive(snapshot);

  const toggleMonitoring = () => {
    if (active) {
      void store.stop();
      return;
    }
    if (hasStarted && snapshot?.interface) {
      void store.start(snapshot.interface.id);
      return;
    }
    setPickerOpen(true);
  };

  return (
    <div className="flex h-full">
      <Sidebar current={view} onNavigate={setView} />

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          snapshot={snapshot}
          busy={store.busy}
          onToggleMonitoring={toggleMonitoring}
          onOpenInterfacePicker={() => setPickerOpen(true)}
        />

        <main className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4">
          {store.error ? <ErrorBanner error={store.error} onDismiss={store.dismissError} /> : null}

          {store.loading && !snapshot ? (
            <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-raised)]">
              <Skeleton rows={6} />
            </div>
          ) : (
            <ViewContent view={view} store={store} onNavigate={setView} onStart={toggleMonitoring} />
          )}
        </main>
      </div>

      <InterfacePicker
        open={pickerOpen}
        interfaces={store.interfaces}
        busy={store.busy}
        onSelect={(interfaceId) => {
          setPickerOpen(false);
          void store.start(interfaceId);
        }}
        onClose={() => setPickerOpen(false)}
      />
    </div>
  );
}

/** Renders the current view. */
function ViewContent({
  view,
  store,
  onNavigate,
  onStart,
}: {
  view: ViewId;
  store: EngineStore;
  onNavigate: (view: ViewId) => void;
  onStart: () => void;
}) {
  const snapshot = store.snapshot;

  switch (view) {
    case 'overview':
      return <Overview snapshot={snapshot} onStart={onStart} onOpenConnections={() => onNavigate('connections')} />;

    case 'traffic':
      // The traffic view is the overview's chart at full size, plus the totals it implies.
      return <Overview snapshot={snapshot} onStart={onStart} onOpenConnections={() => onNavigate('connections')} />;

    case 'connections':
      return snapshot ? (
        <Connections snapshot={snapshot} paused={store.paused} onTogglePause={() => store.setPaused(!store.paused)} />
      ) : null;

    case 'pcap':
      return snapshot ? (
        <PcapAnalysis
          snapshot={snapshot}
          busy={store.busy}
          onAnalyze={(path) => void store.analyze(path)}
          onOpenConnections={() => onNavigate('connections')}
        />
      ) : null;

    case 'settings':
      return store.config ? (
        <Settings
          config={store.config}
          capabilities={store.capabilities}
          diagnostics={store.diagnostics}
          busy={store.busy}
          onSave={(config) => void store.saveConfig(config)}
        />
      ) : null;

    case 'interfaces':
      return snapshot ? (
        <Overview snapshot={snapshot} onStart={onStart} onOpenConnections={() => onNavigate('connections')} />
      ) : null;

    default:
      return null;
  }
}
