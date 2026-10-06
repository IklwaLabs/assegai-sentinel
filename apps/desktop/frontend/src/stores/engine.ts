/**
 * The engine store.
 *
 * This is a *cache of the engine's state*, not a second source of truth. The engine owns the
 * flow table, the aggregation and every number; the store holds the latest snapshot so React
 * can render without asking, and forwards user intent as commands.
 *
 * What it deliberately does not do: filter, sort, prioritise or judge. Every field here is
 * either straight from the engine or a UI-only concern such as which pane is open.
 */

import { create } from 'zustand';
import type {
  ApiError,
  AppConfig,
  Capabilities,
  Diagnostics,
  EngineEvent,
  EngineSnapshot,
  NetworkInterface,
} from '@sentinel/types';
import * as api from '@/lib/tauri';

/** The store's shape, named so props can be typed without inference. */
interface EngineStoreShape {
  /** The most recent snapshot, or null before the first one arrives. */
  snapshot: EngineSnapshot | null;
  /** True while the first snapshot is being fetched. */
  loading: boolean;
  /** The last error, cleared when a new command succeeds. */
  error: ApiError | null;
  /** Interfaces for the picker, fetched on demand. */
  interfaces: NetworkInterface[];
  /** Capabilities, fetched once for the diagnostics panel and first-run guidance. */
  capabilities: Capabilities | null;
  /** Data locations, shown in Settings. */
  diagnostics: Diagnostics | null;
  /** Configuration, owned by the engine; saved through a command. */
  config: AppConfig | null;
  /** True while a command is in flight, so buttons can show progress without blocking the view. */
  busy: boolean;
  /** True while the live list is paused, a UI-only concern. */
  paused: boolean;

  initialize: () => Promise<void>;
  start: (interfaceId: string) => Promise<void>;
  stop: () => Promise<void>;
  analyze: (path: string) => Promise<void>;
  refresh: () => Promise<void>;
  loadInterfaces: () => Promise<void>;
  loadDiagnostics: () => Promise<void>;
  saveConfig: (config: AppConfig) => Promise<void>;
  setPaused: (paused: boolean) => void;
  dismissError: () => void;
}

/** Applies an engine event to the cache. */
function applyEvent(state: EngineStoreShape, event: EngineEvent): Partial<EngineStoreShape> {
  switch (event.kind) {
    case 'snapshot':
      return { snapshot: event.payload, config: event.payload.config, loading: false };
    case 'stateChanged': {
      // A state change alone does not carry the counters, so the view keeps the last snapshot
      // and only reacts to the state. The engine sends a snapshot on its next tick, so this
      // avoids a request-response round trip on every start and stop.
      const previous = state.snapshot;
      if (!previous) return { loading: false };
      return { snapshot: { ...previous, state: event.payload } };
    }
    case 'notice':
      return {
        error: {
          kind: 'engine',
          title: event.payload.title,
          summary: event.payload.summary,
          hint: event.payload.hint,
          details: event.payload.details,
        },
      };
    default:
      return {};
  }
}

/**
 * Normalises a rejected command into the store's error field.
 *
 * Every call in `lib/tauri.ts` already rejects with an `ApiError`, so the value is typed at the
 * source. The guard exists for the one case that bypasses it: a `panic` in a command handler,
 * which Tauri surfaces as a plain string.
 */
function describe(error: unknown): ApiError {
  if (typeof error === 'object' && error !== null && 'title' in error && 'summary' in error) {
    return error as ApiError;
  }
  return {
    kind: 'engine',
    title: 'Sentinel hit an unexpected fault',
    summary: 'A command failed in a way Sentinel does not recognise. This is a bug.',
    hint: ['Retry the action.', 'Report the problem with your logs attached.'],
    details: error instanceof Error ? error.message : String(error),
  };
}

/** The store's shape, exported so components can type their props without inference. */
export type EngineStore = EngineStoreShape;

/** The engine cache: the latest snapshot plus UI-only concerns. */
export const useEngine = create<EngineStoreShape>((set, get) => ({
  snapshot: null,
  loading: true,
  error: null,
  interfaces: [],
  capabilities: null,
  diagnostics: null,
  config: null,
  busy: false,
  paused: false,

  initialize: async () => {
    set({ loading: true, error: null });
    try {
      // One subscription for the life of the window. Re-subscribing would give the renderer
      // two streams of updates for one engine.
      await api.subscribeToEngine((event) => {
        set((state) => applyEvent(state, event));
      });

      const snapshot = await api.getSnapshot();
      set({ snapshot, config: snapshot.config, loading: false });
    } catch (error) {
      set({ error: describe(error), loading: false });
    }
  },

  start: async (interfaceId) => {
    set({ busy: true, error: null });
    try {
      await api.startMonitoring(interfaceId);
      await get().refresh();
    } catch (error) {
      set({ error: describe(error) });
    } finally {
      set({ busy: false });
    }
  },

  stop: async () => {
    set({ busy: true, error: null });
    try {
      await api.stopMonitoring();
      await get().refresh();
    } catch (error) {
      set({ error: describe(error) });
    } finally {
      set({ busy: false });
    }
  },

  analyze: async (path) => {
    set({ busy: true, error: null, paused: false });
    try {
      await api.analyzeCapture(path);
      await get().refresh();
    } catch (error) {
      set({ error: describe(error) });
    } finally {
      set({ busy: false });
    }
  },

  refresh: async () => {
    try {
      const snapshot = await api.getSnapshot();
      set({ snapshot, config: snapshot.config });
    } catch (error) {
      set({ error: describe(error) });
    }
  },

  loadInterfaces: async () => {
    try {
      const interfaces = await api.listInterfaces();
      set({ interfaces });
    } catch (error) {
      set({ error: describe(error) });
    }
  },

  loadDiagnostics: async () => {
    try {
      const [caps, diagnostics] = await Promise.all([api.capabilities(), api.getDiagnostics()]);
      set({ capabilities: caps, diagnostics });
    } catch (error) {
      set({ error: describe(error) });
    }
  },

  saveConfig: async (config) => {
    set({ busy: true, error: null });
    try {
      const applied = await api.saveSettings(config);
      set({ config: applied });
    } catch (error) {
      set({ error: describe(error) });
    } finally {
      set({ busy: false });
    }
  },

  setPaused: (paused) => set({ paused }),
  dismissError: () => set({ error: null }),
}));

/**
 * True when the engine is capturing or analysing.
 *
 * A selector rather than a value so a component subscribing to only this does not re-render
 * on every snapshot.
 */
export function isActive(snapshot: EngineSnapshot | null): boolean {
  if (!snapshot) return false;
  return snapshot.state.state === 'monitoring' || snapshot.state.state === 'analyzing';
}

/** A short label for the session, used in the top bar and the status pill. */
export function stateLabel(snapshot: EngineSnapshot | null): string {
  if (!snapshot) return 'Starting';
  switch (snapshot.state.state) {
    case 'idle':
      return 'Not monitoring';
    case 'preparing':
      return 'Preparing';
    case 'monitoring':
      return `Monitoring ${snapshot.state.detail.interfaceName}`;
    case 'analyzing':
      return `Analyzing ${snapshot.state.detail.fileName}`;
    case 'failed':
      return `Stopped: ${snapshot.state.detail.reason}`;
    default:
      return 'Unknown';
  }
}
