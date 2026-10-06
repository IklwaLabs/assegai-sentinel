/**
 * The error banner.
 *
 * Shows a failed command with the engine's own wording: title, what happened, and what to do.
 * The technical detail sits behind a disclosure, because a user does not need a driver error
 * code to fix a permission problem, but a bug report does need it.
 */

import { useState } from 'react';
import type { ApiError } from '@sentinel/types';
import { Button } from '@/components/ui';

const KIND_ACCENT: Record<ApiError['kind'], string> = {
  permission: 'var(--severity-high)',
  driver: 'var(--severity-medium)',
  interface: 'var(--severity-low)',
  configuration: 'var(--severity-medium)',
  storage: 'var(--severity-medium)',
  invalidState: 'var(--text-muted)',
  engine: 'var(--severity-critical)',
  unsupported: 'var(--text-muted)',
};

export function ErrorBanner({ error, onDismiss }: { error: ApiError; onDismiss: () => void }) {
  const [showDetails, setShowDetails] = useState(false);

  return (
    <div role="alert" className="rail bg-[var(--surface-raised)]" style={{ borderLeftColor: KIND_ACCENT[error.kind] }}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-[var(--text-primary)]">{error.title}</p>
          <p className="mt-0.5 text-[13px] text-[var(--text-secondary)] text-balance">{error.summary}</p>

          {error.hint.length > 0 && (
            <ul className="mt-2 space-y-1">
              {error.hint.map((hint) => (
                <li key={hint} className="flex gap-2 text-[12px] text-[var(--text-muted)]">
                  <span aria-hidden className="text-[var(--text-faint)]">
                    →
                  </span>
                  <span>{hint}</span>
                </li>
              ))}
            </ul>
          )}

          {error.details ? (
            <div className="mt-2">
              <button
                type="button"
                onClick={() => setShowDetails((value) => !value)}
                className="text-[12px] text-[var(--text-muted)] underline decoration-dotted underline-offset-2 hover:text-[var(--text-secondary)]"
              >
                {showDetails ? 'Hide details' : 'Show details'}
              </button>
              {showDetails ? (
                <pre className="mono mt-1.5 max-h-40 overflow-auto rounded border border-[var(--border-subtle)] bg-[var(--surface-base)] p-2 text-[11px] leading-relaxed text-[var(--text-muted)]">
                  {error.details}
                </pre>
              ) : null}
            </div>
          ) : null}
        </div>

        <Button variant="ghost" onClick={onDismiss} title="Dismiss">
          Dismiss
        </Button>
      </div>
    </div>
  );
}
