/**
 * TypeScript mirror of the Rust API contract.
 *
 * These types are hand-written to match `sentinel-api`. They are not generated, so a change on
 * either side is a deliberate act: the frontend is a renderer, and its only contract is the
 * shape of the data the engine sends it.
 *
 * Conventions that must match the Rust side:
 * - every field is `camelCase`
 * - timestamps are microseconds since the Unix epoch, as a number
 * - byte counts are `u64` on the wire, so they arrive as JSON numbers and can exceed
 *   `Number.MAX_SAFE_INTEGER` on a long-running machine; see `safeBytes` in `lib/format.ts`
 */

/** Session state, mirroring `sentinel_core::session::SessionState`. */
export type SessionState =
  | { state: 'idle' }
  | { state: 'preparing' }
  | { state: 'monitoring'; detail: { interface: string; interfaceName: string } }
  | { state: 'analyzing'; detail: { fileName: string } }
  | { state: 'failed'; detail: { reason: string } };

/** Device classification. */
export type InterfaceKind = 'loopback' | 'ethernet' | 'wireless' | 'tunnel' | 'virtual' | 'other';

/** One address configured on an interface. */
export interface InterfaceAddress {
  addr: string;
  prefixLen: number;
}

/** A network interface, mirroring `sentinel_common::net::NetworkInterface`. */
export interface NetworkInterface {
  id: string;
  name: string;
  description: string | null;
  addresses: InterfaceAddress[];
  mac: string | null;
  kind: InterfaceKind;
  isUp: boolean;
  isLoopback: boolean;
  isVirtual: boolean;
  captureReady: boolean;
  captureBlockedReason: string | null;
}

/** Which capture driver is in use. */
export type CaptureBackend = 'npcap' | 'libpcap' | 'bpf' | 'androidTun' | 'unsupported';

/** Privilege state of the running process. */
export type PrivilegeState = 'elevated' | 'notElevated' | 'unknown';

/** Platform capabilities, mirroring `sentinel_platform::capabilities::Capabilities`. */
export interface Capabilities {
  backend: CaptureBackend;
  libraryPresent: boolean;
  requiresElevation: boolean;
  privilege: PrivilegeState;
  loopbackSupported: boolean;
  maxSnaplen: number;
  notes: string[];
}

/** One connection row, mirroring `sentinel_core::event::ConnectionRow`. */
export interface ConnectionRow {
  id: string;
  source: string;
  destination: string;
  initiatorKnown: boolean;
  local: string | null;
  remote: string | null;
  protocol: string;
  domain: string | null;
  service: string | null;
  process: string | null;
  state: string;
  uploadBytes: number;
  downloadBytes: number;
  packets: number;
  firstSeenUs: number;
  lastSeenUs: number;
  riskScore: number | null;
  alertCount: number;
}

/** One second of aggregated traffic. */
export interface TrafficPoint {
  atUs: number;
  uploadBytes: number;
  downloadBytes: number;
  packets: number;
}

/** Ingress queue accounting. */
export interface QueueAccounting {
  accepted: number;
  dropped: number;
  highWatermark: number;
}

/** Pipeline stage counters. */
export interface PipelineCounters {
  packetsSeen: number;
  packetsDecoded: number;
  decodeErrors: number;
  packetsWithoutFlow: number;
  truncatedPackets: number;
  flowsCreated: number;
  sweeps: number;
}

/** Pipeline and queue statistics. */
export interface PipelineStats {
  counters: PipelineCounters;
  flowsActive: number;
  queue: QueueAccounting;
}

/** Engine-level counters. */
export interface MetricsSnapshot {
  packetsCaptured: number;
  bytesCaptured: number;
  packetsDropped: number;
  packetsDecoded: number;
  decodeErrors: number;
  queueHighWatermark: number;
  flowsActive: number;
  flowsCreated: number;
  flowsEvicted: number;
  flowsExpired: number;
  packetsWritten: number;
  uiEventsEmitted: number;
  capturing: boolean;
  backendDropped: number;
}

/** Retention options, as the engine serializes them. */
export type RetentionPeriod = '24h' | '7d' | '30d' | '90d' | 'forever' | { custom: number };

/**
 * The named retention options, excluding the arbitrary-day form.
 *
 * A select can only present named choices. A custom period arrives from a future control that
 * asks for a number of days, not from this list, so the two are separate types.
 */
export type RetentionChoice = Exclude<RetentionPeriod, { custom: number }>;

/** Packet capture behaviour. */
export interface CaptureConfig {
  interfaceId: string | null;
  snaplen: number;
  promiscuous: boolean;
  readTimeoutMs: number;
  queueCapacity: number;
  flowIdleTimeoutSecs: number;
  maxTrackedFlows: number;
  uiUpdateHz: number;
}

/** Storage retention behaviour. */
export interface RetentionConfig {
  flows: RetentionPeriod;
  trafficSamples: RetentionPeriod;
}

/** Privacy switches. */
export interface PrivacyConfig {
  capturePayloadSamples: boolean;
  redactLocalAddressesInExports: boolean;
}

/** Appearance preferences. */
export interface AppearanceConfig {
  theme: 'dark' | 'system';
  compactTables: boolean;
}

/** Log verbosity. */
export type LogLevel = 'error' | 'warn' | 'info' | 'debug' | 'trace';

/** Storage and diagnostics settings. */
export interface AdvancedConfig {
  logLevel: LogLevel;
  walMode: boolean;
  writeBatchSize: number;
  maxDbSizeMb: number;
}

/** The complete configuration. */
export interface AppConfig {
  version: number;
  capture: CaptureConfig;
  retention: RetentionConfig;
  privacy: PrivacyConfig;
  appearance: AppearanceConfig;
  advanced: AdvancedConfig;
}

/** Everything a view needs in one payload. */
export interface EngineSnapshot {
  state: SessionState;
  interface: NetworkInterface | null;
  totalUploadBytes: number;
  totalDownloadBytes: number;
  totalPackets: number;
  firstSeenUs: number;
  lastSeenUs: number;
  uploadBps: number;
  downloadBps: number;
  traffic: TrafficPoint[];
  connections: ConnectionRow[];
  flowsActive: number;
  stats: PipelineStats;
  metrics: MetricsSnapshot;
  config: AppConfig;
}

/** Failure categories the UI branches on. */
export type ApiErrorKind =
  | 'permission'
  | 'driver'
  | 'interface'
  | 'configuration'
  | 'storage'
  | 'invalidState'
  | 'engine'
  | 'unsupported';

/** An error returned by a Tauri command. */
export interface ApiError {
  kind: ApiErrorKind;
  title: string;
  summary: string;
  hint: string[];
  details: string | null;
}

/** Where Sentinel keeps its data. */
export interface Diagnostics {
  dataDirectory: string;
  databaseFile: string;
  logsDirectory: string;
  exportsDirectory: string;
  warnings: string[];
}

/** Engine events pushed to the window, mirroring `sentinel_core::event::EngineEvent`. */
export type EngineEvent =
  | { kind: 'stateChanged'; payload: SessionState }
  | { kind: 'snapshot'; payload: EngineSnapshot }
  | { kind: 'notice'; payload: { title: string; summary: string; hint: string[]; details: string | null } };

/**
 * Renders an interface's addresses in the engine's own format: `192.168.1.10/24, fe80::1/64`.
 *
 * Lives beside the types so a frontend cannot invent a second format, and is a function
 * rather than a field because it is presentation rather than state.
 */
export function formatAddresses(addresses: InterfaceAddress[]): string {
  if (addresses.length === 0) return 'No address';
  return addresses.map((address) => `${address.addr}/${address.prefixLen}`).join(', ');
}
