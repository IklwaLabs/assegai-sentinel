/**
 * Tauri bridge.
 *
 * Every call the frontend makes to the engine goes through this file. Two reasons:
 * the window never touches `invoke` directly, and a failure always arrives in the same
 * `ApiError` shape, so no component has to parse a stringified Rust error.
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { ApiError, ApiErrorKind, AppConfig, Capabilities, Diagnostics, EngineEvent, EngineSnapshot, NetworkInterface, SessionState } from '@sentinel/types';

const ERROR_KINDS: readonly ApiErrorKind[] = [
  'permission',
  'driver',
  'interface',
  'configuration',
  'storage',
  'invalidState',
  'engine',
  'unsupported',
];

/** The event channel the Rust side emits on. */
export const ENGINE_EVENT = 'sentinel://event';

function isApiError(value: unknown): value is ApiError {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<ApiError>;
  return (
    typeof candidate.title === 'string' &&
    typeof candidate.summary === 'string' &&
    Array.isArray(candidate.hint) &&
    (candidate.kind === undefined || ERROR_KINDS.includes(candidate.kind))
  );
}

/**
 * An `ApiError` that is also a real `Error`.
 *
 * The wire shape stays a plain serializable object, so Rust and TypeScript agree on the fields.
 * Extending `Error` means the value can be thrown, which keeps `catch` blocks honest: a
 * rejected promise carries something that survives `instanceof Error` and shows a useful name in
 * a stack trace instead of appearing as an anonymous object.
 */
export class CommandError extends Error implements ApiError {
  readonly kind: ApiErrorKind;
  readonly title: string;
  readonly summary: string;
  readonly hint: string[];
  readonly details: string | null;

  constructor(error: ApiError) {
    super(`${error.title}: ${error.summary}`);
    this.name = 'CommandError';
    this.kind = error.kind;
    this.title = error.title;
    this.summary = error.summary;
    this.hint = error.hint;
    this.details = error.details;
  }
}

/**
 * Normalises anything thrown by a command into an `ApiError`.
 *
 * Tauri serialises a `Result::Err` payload verbatim, so a typed error arrives intact. Anything
 * else is a bug or a transport failure, and is reported as such rather than being shown raw.
 */
function toApiError(value: unknown, command: string): CommandError {
  if (value instanceof CommandError) return value;
  if (isApiError(value)) return new CommandError(value);

  const text = value instanceof Error ? value.message : typeof value === 'string' ? value : JSON.stringify(value);

  return new CommandError({
    kind: 'engine',
    title: 'Sentinel could not complete that request',
    summary: `The command \`${command}\` did not return a usable result.`,
    hint: ['Retry the action.', 'If it keeps happening, export your logs from Settings and report the problem.'],
    details: text ?? null,
  });
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw toApiError(error, command);
  }
}

/** Lists interfaces available for monitoring. */
export async function listInterfaces(): Promise<NetworkInterface[]> {
  return call<NetworkInterface[]>('list_interfaces');
}

/** Reports what packet capture is possible in this process. */
export async function capabilities(): Promise<Capabilities> {
  return call<Capabilities>('capabilities');
}

/** Starts monitoring an interface. */
export async function startMonitoring(interfaceId: string): Promise<SessionState> {
  return call<SessionState>('start_monitoring', { interfaceId });
}

/** Stops the current session. */
export async function stopMonitoring(): Promise<void> {
  await call<void>('stop_monitoring');
}

/** Analyses a PCAP file offline. */
export async function analyzeCapture(path: string): Promise<SessionState> {
  return call<SessionState>('analyze_capture', { path });
}

/** Fetches a full snapshot. */
export async function getSnapshot(): Promise<EngineSnapshot> {
  return call<EngineSnapshot>('get_snapshot');
}

/** Reads the effective configuration. */
export async function getSettings(): Promise<AppConfig> {
  return call<AppConfig>('get_settings');
}

/** Replaces the effective configuration and writes it to disk. */
export async function saveSettings(config: AppConfig): Promise<AppConfig> {
  return call<AppConfig>('save_settings', { config });
}

/** Returns the application directories and start-up warnings. */
export async function getDiagnostics(): Promise<Diagnostics> {
  return call<Diagnostics>('get_diagnostics');
}

/**
 * Subscribes to engine events.
 *
 * Returns the unsubscribe function. The caller owns the lifetime: the store subscribes once
 * for the life of the window, because a second stream feeding one renderer would double every
 * update.
 */
export async function subscribeToEngine(handler: (event: EngineEvent) => void): Promise<UnlistenFn> {
  return listen<EngineEvent>(ENGINE_EVENT, (message) => {
    handler(message.payload);
  });
}
