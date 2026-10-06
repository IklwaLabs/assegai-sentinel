/**
 * The sidebar.
 *
 * Navigation is grouped by intent, not by implementation: what is happening now, what is
 * wrong, what to investigate, what to configure. Groups that have nothing in them yet are
 * absent rather than greyed out, because a disabled item is a promise the product has not kept.
 */

import { Badge } from '@/components/ui';

export type ViewId =
  | 'overview'
  | 'traffic'
  | 'connections'
  | 'devices'
  | 'dns'
  | 'threats'
  | 'alerts'
  | 'incidents'
  | 'intelligence'
  | 'pcap'
  | 'timeline'
  | 'map'
  | 'interfaces'
  | 'rules'
  | 'reports'
  | 'settings';

interface NavItem {
  id: ViewId;
  label: string;
  /** Shown on the right, e.g. a count. Only used where a number already exists. */
  badge?: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

/**
 * The navigation tree.
 *
 * Only views v0.1 actually renders are listed. Devices, DNS, threats and the investigation
 * views arrive with their milestones, and adding them here is how they become reachable.
 */
export const NAV_GROUPS: NavGroup[] = [
  { label: 'Overview', items: [{ id: 'overview', label: 'Overview' }] },
  {
    label: 'Monitor',
    items: [
      { id: 'traffic', label: 'Traffic' },
      { id: 'connections', label: 'Connections' },
    ],
  },
  {
    label: 'Investigate',
    items: [{ id: 'pcap', label: 'PCAP analysis' }],
  },
  {
    label: 'System',
    items: [
      { id: 'interfaces', label: 'Interfaces' },
      { id: 'settings', label: 'Settings' },
    ],
  },
];

export function Sidebar({ current, onNavigate }: { current: ViewId; onNavigate: (view: ViewId) => void }) {
  return (
    <nav
      aria-label="Primary"
      className="flex h-full w-[var(--sidebar-width)] shrink-0 flex-col border-r border-[var(--border-subtle)] bg-[var(--surface-base)]"
    >
      <div className="flex h-[var(--topbar-height)] items-center gap-2 px-4">
        {/* The mark echoes the application icon: a restrained arc, not a logo. */}
        <span aria-hidden className="relative inline-block size-4">
          <span className="absolute inset-0 rounded-full border border-[var(--border-strong)]" />
          <span className="absolute inset-0 rounded-full border border-transparent border-t-[var(--accent)] border-r-[var(--accent)] rotate-45" />
        </span>
        <span className="text-[13px] font-semibold tracking-tight text-[var(--text-primary)]">Sentinel</span>
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4">
            <p className="label px-2 pb-1.5">{group.label}</p>
            <ul className="flex flex-col gap-px">
              {group.items.map((item) => {
                const active = item.id === current;
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      aria-current={active ? 'page' : undefined}
                      onClick={() => onNavigate(item.id)}
                      className={`flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-[13px] transition-colors ${
                        active
                          ? 'bg-[var(--surface-overlay)] font-medium text-[var(--text-primary)]'
                          : 'text-[var(--text-secondary)] hover:bg-[var(--surface-raised)] hover:text-[var(--text-primary)]'
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        {active ? <span aria-hidden className="size-1.5 rounded-full bg-[var(--accent)]" /> : null}
                        {item.label}
                      </span>
                      {item.badge ? <Badge tone="neutral">{item.badge}</Badge> : null}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>

      {/* Privacy is a product promise, so it is stated where it cannot be scrolled past. */}
      <div className="border-t border-[var(--border-subtle)] px-4 py-3">
        <p className="text-[11px] leading-relaxed text-[var(--text-muted)]">
          Local mode
          <br />
          <span className="text-[var(--text-faint)]">Cloud sync off · no account</span>
        </p>
      </div>
    </nav>
  );
}
