/**
 * The traffic chart.
 *
 * Two stacked areas, upload and download, on one axis, drawn with ECharts. Two rules:
 * the series is already aggregated by the engine into one-second buckets, so this draws data
 * rather than aggregating it; and an empty series renders a flat baseline rather than nothing,
 * so the panel does not collapse when traffic stops.
 */

import { useEffect, useMemo, useRef } from 'react';
import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { GridComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import type { EChartsOption } from 'echarts';
import type { TrafficPoint } from '@sentinel/types';
import { bytes } from '@/lib/format';

echarts.use([LineChart, GridComponent, TooltipComponent, CanvasRenderer]);

const SPLIT_COLOR = 'rgba(30, 35, 43, 1)';
const DOWNLOAD_COLOR = '#9ca3af';
const UPLOAD_COLOR = '#F97316';
const LABEL_COLOR = '#6b7280';
const TEXT_COLOR = '#f3f4f6';

/** Formats a bucket timestamp as a short axis or tooltip label. */
function stamp(micros: number): string {
  return new Date(micros / 1000).toLocaleTimeString(undefined, { minute: '2-digit', second: '2-digit' });
}

export function TrafficChart({ points, height = 200 }: { points: TrafficPoint[]; height?: number }) {
  const container = useRef<HTMLDivElement | null>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  // Rebuilt only when the engine sends new buckets, so typing in another pane does not
  // recreate the series.
  const option = useMemo<EChartsOption>(() => {
    const labels = points.map((point) => stamp(point.atUs));

    return {
      animation: false,
      grid: { top: 8, right: 8, bottom: 20, left: 56 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: '#161a20',
        borderColor: '#242a33',
        textStyle: { color: TEXT_COLOR, fontSize: 12 },
        // The category axis already carries the label, so the tooltip reads the heading
        // from the first series entry rather than resolving an index back to a time.
        // `axisValue`/`name` are not on ECharts' public `CallbackDataParams` type, so the
        // entry is widened once here rather than cast at every access.
        formatter: (params) => formatTooltip(params),
      },
      xAxis: {
        type: 'category',
        data: labels,
        axisLine: { lineStyle: { color: SPLIT_COLOR } },
        axisTick: { show: false },
        axisLabel: { color: LABEL_COLOR, fontSize: 10, hideOverlap: true },
      },
      yAxis: {
        type: 'value',
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: LABEL_COLOR, fontSize: 10, formatter: (value: number) => bytes(value) },
        splitLine: { lineStyle: { color: SPLIT_COLOR } },
      },
      series: [
        {
          name: 'Download',
          type: 'line',
          smooth: 0.2,
          showSymbol: false,
          stack: 'total',
          lineStyle: { color: DOWNLOAD_COLOR, width: 1.5 },
          areaStyle: { color: 'rgba(156, 163, 175, 0.14)' },
          data: points.map((point) => point.downloadBytes),
        },
        {
          name: 'Upload',
          type: 'line',
          smooth: 0.2,
          showSymbol: false,
          stack: 'total',
          lineStyle: { color: UPLOAD_COLOR, width: 1.5 },
          areaStyle: { color: 'rgba(249, 115, 22, 0.16)' },
          data: points.map((point) => point.uploadBytes),
        },
      ],
    };
  }, [points]);

  useEffect(() => {
    if (!container.current) return;

    chart.current ??= echarts.init(container.current, undefined, { renderer: 'canvas' });

    // The webview reports a size only after layout, and the window is resizable.
    const observer = new ResizeObserver(() => chart.current?.resize());
    observer.observe(container.current);

    return () => {
      observer.disconnect();
      chart.current?.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    chart.current?.setOption(option, { notMerge: false, lazyUpdate: true });
  }, [option]);

  if (points.length === 0) {
    return (
      <div className="flex items-center justify-center px-4 text-[12px] text-[var(--text-faint)]" style={{ height }}>
        No traffic recorded yet
      </div>
    );
  }

  return <div ref={container} style={{ height }} role="img" aria-label="Upload and download traffic over time" />;
}

/** One series entry as ECharts reports it, with the fields the tooltip actually reads. */
interface TooltipEntry {
  axisValue?: unknown;
  seriesName?: unknown;
  value?: unknown;
}

/**
 * Renders the ECharts axis tooltip as plain lines.
 *
 * The category axis already carries the formatted label, so the heading is read from the first
 * entry rather than resolved from an index back to a time. ECharts' public parameter type omits
 * these fields, so the payload is narrowed here once instead of being cast at every access.
 */
function formatTooltip(params: unknown): string {
  if (!Array.isArray(params) || params.length === 0) return '';

  const entries = params as TooltipEntry[];
  const heading = typeof entries[0]?.axisValue === 'string' ? entries[0].axisValue : '';

  const rows = entries.map((entry) => {
    // On a category axis ECharts reports `[categoryIndex, value]`, so the data is the last
    // element. `Array.isArray` narrows to `any[]`, so the element is re-checked as unknown
    // rather than trusted.
    const raw: unknown = entry.value;
    const candidate: unknown = Array.isArray(raw) ? lastElement(raw) : raw;
    const value = typeof candidate === 'number' ? candidate : 0;
    const name = typeof entry.seriesName === 'string' ? entry.seriesName : 'Value';
    return `${name}: ${bytes(value)}`;
  });

  return [heading, ...rows].filter((line) => line.length > 0).join('<br/>');
}

/** The last element of an array of unknown values, or `undefined` when it is empty. */
function lastElement(values: unknown[]): unknown {
  return values.at(-1);
}
