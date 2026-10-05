/**
 * Settings.
 *
 * Only settings that change behaviour are shown, grouped by the question they answer. Each
 * control states its effect, because a security tool that silently changes what is collected
 * is not one people can trust.
 */

import { useEffect, useState } from 'react';
import type { AppConfig, Capabilities, Diagnostics, RetentionChoice } from '@sentinel/types';
import { Badge, Button, Field, Panel, Select, Toggle } from '@/components/ui';

const RETENTION_OPTIONS: { value: RetentionChoice; label: string }[] = [
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: 'forever', label: 'Keep forever' },
];

const LOG_LEVELS: { value: AppConfig['advanced']['logLevel']; label: string }[] = [
  { value: 'error', label: 'Errors only' },
  { value: 'warn', label: 'Warnings' },
  { value: 'info', label: 'Normal' },
  { value: 'debug', label: 'Verbose' },
  { value: 'trace', label: 'Very verbose' },
];

export function Settings({
  config,
  capabilities,
  diagnostics,
  busy,
  onSave,
}: {
  config: AppConfig;
  capabilities: Capabilities | null;
  diagnostics: Diagnostics | null;
  busy: boolean;
  onSave: (config: AppConfig) => void;
}) {
  const [draft, setDraft] = useState(config);

  // The engine is the source of truth: when it applies or repairs a value, the draft follows.
  useEffect(() => setDraft(config), [config]);

  const dirty = JSON.stringify(draft) !== JSON.stringify(config);

  const update = <K extends keyof AppConfig>(key: K, value: AppConfig[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-[15px] font-medium text-[var(--text-primary)]">Settings</h1>
          <p className="mt-0.5 text-[12px] text-[var(--text-muted)]">All monitoring data stays on this machine.</p>
        </div>
        <Button variant="primary" disabled={!dirty || busy} onClick={() => onSave(draft)}>
          {dirty ? 'Save changes' : 'Saved'}
        </Button>
      </div>

      <Panel title="Privacy">
        <div className="px-4 pb-3">
          <Field label="Local mode" hint="Sentinel has no account, sends no telemetry, and works without an internet connection.">
            <Badge tone="safe">Active</Badge>
          </Field>

          <Field
            label="Keep payload samples"
            hint="Stores a small excerpt of packet payloads as evidence. Off by default: Sentinel is designed to work without retaining payload bytes."
          >
            <Toggle
              checked={draft.privacy.capturePayloadSamples}
              onChange={(value) => update('privacy', { ...draft.privacy, capturePayloadSamples: value })}
              label="Retain payload samples for evidence"
            />
          </Field>
        </div>
      </Panel>

      <Panel title="Capture">
        <div className="px-4 pb-3">
          <Field label="Update rate" hint="How often the interface refreshes. Lower values use less CPU on a busy network.">
            <Select
              value={draft.capture.uiUpdateHz}
              onChange={(value) => update('capture', { ...draft.capture, uiUpdateHz: value })}
              options={[1, 2, 4, 8, 15, 30].map((hz) => ({ value: hz, label: `${hz} per second` }))}
            />
          </Field>

          <Field label="Promiscuous mode" hint="Captures traffic not addressed to this machine. Requires elevated privileges and sees more, unrelated traffic.">
            <Toggle
              checked={draft.capture.promiscuous}
              onChange={(value) => update('capture', { ...draft.capture, promiscuous: value })}
              label="Capture all traffic on the selected adapter"
            />
          </Field>

          <Field label="Snapshot length" hint="Bytes captured per frame. 65535 keeps whole frames, including jumbo frames.">
            <Select
              value={draft.capture.snaplen}
              onChange={(value) => update('capture', { ...draft.capture, snaplen: value })}
              options={[1500, 9000, 65535].map((size) => ({ value: size, label: `${size} bytes` }))}
            />
          </Field>
        </div>
      </Panel>

      <Panel title="Retention">
        <div className="px-4 pb-3">
          <Field label="Connection history" hint="Older connections are deleted automatically. Sentinel never stores raw packets.">
            <Select
              value={namedChoice(draft.retention.flows)}
              onChange={(value) => update('retention', { ...draft.retention, flows: value })}
              options={RETENTION_OPTIONS}
            />
          </Field>

          <Field label="Traffic history" hint="Controls the traffic chart's stored samples. Smaller values keep the database small.">
            <Select
              value={namedChoice(draft.retention.trafficSamples)}
              onChange={(value) => update('retention', { ...draft.retention, trafficSamples: value })}
              options={RETENTION_OPTIONS}
            />
          </Field>
        </div>
      </Panel>

      <Panel title="Diagnostics">
        <div className="px-4 pb-3">
          <Field label="Log detail" hint="Applied on the next start. Verbose logging is useful when reporting a problem.">
            <Select
              value={draft.advanced.logLevel}
              onChange={(value) => update('advanced', { ...draft.advanced, logLevel: value })}
              options={LOG_LEVELS}
            />
          </Field>

          {capabilities ? (
            <div className="flex flex-col gap-1.5 py-3 text-[12px]">
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-[var(--text-muted)]">Capture driver</span>
                <span className="mono text-[var(--text-primary)]">
                  {capabilities.backend} {capabilities.libraryPresent ? '' : '(not installed)'}
                </span>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-[var(--text-muted)]">Process privileges</span>
                <span className="mono text-[var(--text-primary)]">{capabilities.privilege}</span>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-[var(--text-muted)]">Capture available now</span>
                <span className="mono text-[var(--text-primary)]">{capabilities.libraryPresent && (!capabilities.requiresElevation || capabilities.privilege === 'elevated') ? 'yes' : 'no'}</span>
              </div>
              {capabilities.notes.map((note) => (
                <p key={note} className="text-[12px] text-[var(--text-faint)]">
                  {note}
                </p>
              ))}
            </div>
          ) : null}

          {diagnostics ? (
            <div className="flex flex-col gap-1.5 py-3 text-[12px]">
              <PathRow label="Data" value={diagnostics.dataDirectory} />
              <PathRow label="Database" value={diagnostics.databaseFile} />
              <PathRow label="Logs" value={diagnostics.logsDirectory} />
              <PathRow label="Exports" value={diagnostics.exportsDirectory} />
            </div>
          ) : null}

          {diagnostics?.warnings.map((warning) => (
            <p key={warning} className="py-1 text-[12px] text-[var(--severity-medium)]">
              {warning}
            </p>
          ))}
        </div>
      </Panel>

      <Panel title="About">
        <div className="px-4 py-3 text-[12px] text-[var(--text-muted)]">
          <p>Iklwa Sentinel</p>
          <p className="mt-0.5 text-[var(--text-faint)]">Built by IklwaLabs</p>
        </div>
      </Panel>
    </div>
  );
}

/**
 * Renders a retention period as a named choice the select can display.
 *
 * A custom period has no label in `RETENTION_OPTIONS`, so it falls back to the default rather
 * than showing an empty control. Choosing another option replaces it, which is the only action
 * the select offers.
 */
function namedChoice(period: AppConfig['retention']['flows']): RetentionChoice {
  return RETENTION_OPTIONS.some((option) => option.value === period) ? (period as RetentionChoice) : '30d';
}

/** A read-only path row, selectable so it can be copied. */
function PathRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="shrink-0 text-[var(--text-muted)]">{label}</span>
      <span className="mono truncate text-right text-[var(--text-primary)]" title={value}>
        {value}
      </span>
    </div>
  );
}
