/**
 * Small, shared presentational pieces.
 *
 * Everything here is stateless and takes plain props. A component earns its own file when it
 * needs state or domain knowledge; a wrapper that only renames a prop does not.
 */

import type { ReactNode } from 'react';

/** A titled surface. The only container in the app: no card inside a card. */
export function Panel({
  title,
  actions,
  children,
  className = '',
}: {
  title?: string | undefined;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-[var(--border-default)] bg-[var(--surface-raised)] ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-[var(--border-subtle)] px-4 py-2.5">
          {title ? <h2 className="text-[13px] font-medium text-[var(--text-primary)]">{title}</h2> : <span />}
          {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
        </header>
      )}
      {children}
    </section>
  );
}

/**
 * A single number with a label.
 *
 * Not a "KPI card": no border, no fill, no icon. A row of these reads as a sentence, which is
 * what a person checking on their network wants.
 *
 * Optional props accept `undefined` explicitly, because `exactOptionalPropertyTypes` is on and
 * a caller that conditionally passes `detail={undefined}` should not have to restructure.
 */
export function Stat({
  label,
  value,
  detail,
  tone = 'default',
}: {
  label: string;
  value: string;
  detail?: string | undefined;
  tone?: 'default' | 'accent' | 'warning' | 'muted';
}) {
  const valueColor = {
    default: 'text-[var(--text-primary)]',
    accent: 'text-[var(--accent)]',
    warning: 'text-[var(--severity-medium)]',
    muted: 'text-[var(--text-secondary)]',
  }[tone];

  return (
    <div className="flex flex-col gap-0.5">
      <span className="label">{label}</span>
      <span className={`mono text-[15px] font-medium ${valueColor}`}>{value}</span>
      {detail ? <span className="text-[11px] text-[var(--text-muted)]">{detail}</span> : null}
    </div>
  );
}

/** A neutral status pill. Colour is decorative; the text carries the meaning. */
export function Badge({
  children,
  tone = 'neutral',
  title,
}: {
  children: ReactNode;
  tone?: 'neutral' | 'accent' | 'safe' | 'warning' | 'critical' | 'info';
  title?: string | undefined;
}) {
  const tones = {
    neutral: 'border-[var(--border-strong)] text-[var(--text-secondary)]',
    accent: 'border-[var(--accent-muted)] text-[var(--accent)]',
    safe: 'border-[var(--severity-safe)] text-[var(--severity-safe)]',
    warning: 'border-[var(--severity-medium)] text-[var(--severity-medium)]',
    critical: 'border-[var(--severity-critical)] text-[var(--severity-critical)]',
    info: 'border-[var(--severity-low)] text-[var(--severity-low)]',
  } as const;

  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11px] font-medium ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

/** A small filled dot. Always paired with text, never used alone. */
export function Dot({ tone = 'neutral' }: { tone?: 'neutral' | 'accent' | 'safe' | 'warning' | 'critical' }) {
  const colors = {
    neutral: 'bg-[var(--text-faint)]',
    accent: 'bg-[var(--accent)]',
    safe: 'bg-[var(--severity-safe)]',
    warning: 'bg-[var(--severity-medium)]',
    critical: 'bg-[var(--severity-critical)]',
  } as const;

  return <span aria-hidden className={`inline-block size-1.5 shrink-0 rounded-full ${colors[tone]}`} />;
}

/**
 * An empty state that says what to do next.
 *
 * Every empty state in the product uses this, because "No data" tells a person nothing. Each
 * one names the condition and offers the single action that resolves it.
 */
export function EmptyState({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <p className="text-[13px] font-medium text-[var(--text-secondary)]">{title}</p>
      <p className="max-w-md text-[13px] text-[var(--text-muted)] text-balance">{body}</p>
      {action ? <div className="mt-1">{action}</div> : null}
    </div>
  );
}

/** A skeleton row. Shown while a panel is loading, so the layout does not jump. */
export function Skeleton({ rows = 3, className = '' }: { rows?: number; className?: string }) {
  return (
    <div className={`flex flex-col gap-2 p-4 ${className}`} aria-hidden>
      {Array.from({ length: rows }, (_, index) => (
        <div
          key={index}
          className="h-3 rounded bg-[var(--surface-overlay)]"
          style={{ width: `${92 - index * 11}%`, opacity: 1 - index * 0.15 }}
        />
      ))}
    </div>
  );
}

/** A button. One shape, four weights, so the interface has a single click target language. */
export function Button({
  children,
  onClick,
  variant = 'secondary',
  disabled = false,
  type = 'button',
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  disabled?: boolean;
  type?: 'button' | 'submit';
  title?: string | undefined;
}) {  const variants = {
    primary: 'bg-[var(--accent)] text-[var(--accent-contrast)] hover:bg-[var(--accent-hover)] border-transparent',
    secondary: 'bg-[var(--surface-overlay)] text-[var(--text-primary)] hover:bg-[var(--surface-input)] border-[var(--border-default)]',
    ghost: 'bg-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-overlay)] border-transparent',
    danger: 'bg-transparent text-[var(--severity-critical)] hover:bg-[var(--severity-critical-surface)] border-[var(--severity-critical)]',
  } as const;

  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[13px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]}`}
    >
      {children}
    </button>
  );
}

/** A labelled field row, used in Settings. */
export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5 py-3">
      <span className="text-[13px] font-medium text-[var(--text-primary)]">{label}</span>
      {hint ? <span className="text-[12px] text-[var(--text-muted)]">{hint}</span> : null}
      <div className="mt-1">{children}</div>
    </label>
  );
}

/** A select, styled to match the rest of the interface. */
export function Select<T extends string | number>({
  value,
  onChange,
  options,
  disabled = false,
}: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: string }[];
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={(event) => {
        const next = event.target.value;
        const match = options.find((option) => String(option.value) === next);
        if (match) onChange(match.value);
      }}
      className="mono w-full max-w-xs rounded-md border border-[var(--border-default)] bg-[var(--surface-input)] px-2.5 py-1.5 text-[13px] text-[var(--text-primary)] disabled:opacity-50"
    >
      {options.map((option) => (
        <option key={String(option.value)} value={String(option.value)}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

/** A checkbox with its label, used in Settings. */
export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (checked: boolean) => void; label: string }) {
  return (
    <label className="flex cursor-pointer items-center gap-2.5 py-1 text-[13px] text-[var(--text-primary)]">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="size-3.5 accent-[var(--accent)]"
      />
      {label}
    </label>
  );
}
