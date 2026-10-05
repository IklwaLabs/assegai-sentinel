/**
 * Display formatting.
 *
 * Every number the user sees passes through here, so units and rounding are decided once.
 * The functions are deliberately total: a malformed or absent value renders as an em dash
 * rather than `NaN`, because a security tool showing `NaN` bytes is worse than one showing
 * nothing.
 */

const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'] as const;

/**
 * Formats a byte count.
 *
 * Binary units, because that is what operating system network statistics report, so a number
 * here can be compared with one from the OS without conversion.
 */
export function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${Math.round(value)} B`;

  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < BYTE_UNITS.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

/** Formats a bits-per-second rate. */
export function rate(bitsPerSecond: number | null | undefined): string {
  if (bitsPerSecond === null || bitsPerSecond === undefined || !Number.isFinite(bitsPerSecond) || bitsPerSecond < 0) {
    return '—';
  }
  if (bitsPerSecond < 1000) return `${Math.round(bitsPerSecond)} bps`;

  const units = ['Kbps', 'Mbps', 'Gbps', 'Tbps'] as const;
  let scaled = bitsPerSecond;
  let unit = -1;
  while (scaled >= 1000 && unit < units.length - 1) {
    scaled /= 1000;
    unit += 1;
  }
  return unit < 0 ? `${Math.round(bitsPerSecond)} bps` : `${scaled.toFixed(1)} ${units[unit]}`;
}

/** Formats a duration in microseconds, with a millisecond floor for sub-second spans. */
export function duration(micros: number | null | undefined): string {
  if (micros === null || micros === undefined || !Number.isFinite(micros) || micros < 0) return '—';
  if (micros < 1_000_000) return `${Math.round(micros / 1000)}ms`;

  const seconds = Math.floor(micros / 1_000_000);
  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${String(seconds % 60).padStart(2, '0')}s`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${String(minutes % 60).padStart(2, '0')}m`;

  return `${Math.floor(hours / 24)}d ${String(hours % 24).padStart(2, '0')}h`;
}

/** Converts microseconds since the epoch to a local clock time. */
export function clockTime(micros: number | null | undefined): string {
  if (!micros || micros <= 0) return '—';
  return new Date(micros / 1000).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/** Formats a count with thousands separators. */
export function count(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return new Intl.NumberFormat().format(Math.round(value));
}

/** Formats a percentage with no decimals. */
export function percent(fraction: number | null | undefined): string {
  if (fraction === null || fraction === undefined || !Number.isFinite(fraction)) return '—';
  return `${Math.round(fraction * 100)}%`;
}

/**
 * Renders an endpoint, showing the port in a dimmer weight.
 *
 * Splitting address and port visually keeps a table scannable: the addresses line up, the
 * ports trail.
 */
export function endpoint(value: string | null | undefined): { address: string; port: string | null } {
  if (!value) return { address: '—', port: null };

  // Bracketed IPv6 with a port, as Sentinel's endpoint display produces.
  const bracketed = /^\[([^\]]+)]:(\d+)$/.exec(value);
  if (bracketed?.[1] && bracketed[2]) return { address: bracketed[1], port: bracketed[2] };

  const lastColon = value.lastIndexOf(':');
  const maybePort = lastColon === -1 ? '' : value.slice(lastColon + 1);
  // An unbracketed IPv6 address contains several colons and no port.
  if (lastColon > 0 && /^\d+$/.test(maybePort)) {
    return { address: value.slice(0, lastColon), port: maybePort };
  }
  return { address: value, port: null };
}
