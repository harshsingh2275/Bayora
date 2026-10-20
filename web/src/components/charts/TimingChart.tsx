import React, { useMemo } from 'react';
import type { TimingModeStats } from '../../types/api';

interface TimingChartProps {
  title: string;
  mode: 'isolated' | 'shared';
  stats: TimingModeStats;
  samples?: {
    hit: number[];
    miss: number[];
  };
}

export const TimingChart: React.FC<TimingChartProps> = ({
  title,
  mode,
  stats,
  samples,
}) => {
  const hitSamples = samples?.hit || [];
  const missSamples = samples?.miss || [];

  const { minVal, maxVal, hitPoints, missPoints } = useMemo(() => {
    const all = [...hitSamples, ...missSamples];
    if (all.length === 0) {
      const min = Math.min(stats.median_hit_ms, stats.median_miss_ms) * 0.8 || 0;
      const max = Math.max(stats.median_hit_ms, stats.median_miss_ms) * 1.2 || 100;
      return { minVal: min, maxVal: max, hitPoints: [], missPoints: [] };
    }
    const min = Math.max(0, Math.min(...all) * 0.9);
    const max = Math.max(...all) * 1.05;

    // Deterministic pseudo-jitter based on index
    const hitPts = hitSamples.map((v, i) => {
      const jitter = ((i * 7) % 17) - 8;
      return { val: v, jitter };
    });
    const missPts = missSamples.map((v, i) => {
      const jitter = ((i * 11) % 17) - 8;
      return { val: v, jitter };
    });

    return { minVal: min, maxVal: max, hitPoints: hitPts, missPoints: missPts };
  }, [hitSamples, missSamples, stats.median_hit_ms, stats.median_miss_ms]);

  const width = 640;
  const height = 180;
  const padding = { top: 30, right: 30, bottom: 40, left: 70 };
  const plotWidth = width - padding.left - padding.right;

  const scaleX = (val: number) => {
    if (maxVal === minVal) return padding.left + plotWidth / 2;
    return padding.left + ((val - minVal) / (maxVal - minVal)) * plotWidth;
  };

  const hitY = 65;
  const missY = 125;

  const isLeak = stats.verdict === 'leak_detected';

  return (
    <div
      style={{
        border: '1px solid var(--color-border-subtle)',
        backgroundColor: 'var(--color-bg-surface)',
        padding: 'var(--space-5)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--space-4)',
      }}
    >
      {/* Mode Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          flexWrap: 'wrap',
          gap: 'var(--space-2)',
        }}
      >
        <div>
          <div
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              fontWeight: 600,
              color: 'var(--color-text-primary)',
            }}
          >
            {title}
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              color: 'var(--color-text-muted)',
              marginTop: '2px',
            }}
          >
            Mode: {mode.toUpperCase()} · N={stats.n_hit} Hits / N={stats.n_miss} Misses
          </div>
        </div>

        {/* Verdict Badge */}
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-xs)',
            fontWeight: 700,
            textTransform: 'uppercase',
            padding: '3px 8px',
            border: `1px solid ${
              isLeak ? 'var(--color-danger)' : 'var(--color-primary)'
            }`,
            backgroundColor: isLeak
              ? 'var(--color-danger-soft)'
              : 'var(--color-primary-soft)',
            color: isLeak ? 'var(--color-danger)' : 'var(--color-primary)',
          }}
        >
          {isLeak ? 'Leak Detected (P < 0.01)' : 'Indistinguishable (No Leak)'}
        </div>
      </div>

      {/* SVG Strip Plot */}
      <div style={{ width: '100%', overflowX: 'auto' }}>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          style={{ width: '100%', maxWidth: `${width}px`, height: 'auto', display: 'block' }}
          role="img"
          aria-label={`Latency distribution strip plot for ${mode} mode`}
        >
          {/* Background grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((pct) => {
            const val = minVal + pct * (maxVal - minVal);
            const x = scaleX(val);
            return (
              <g key={pct}>
                <line
                  x1={x}
                  y1={padding.top - 10}
                  x2={x}
                  y2={height - padding.bottom}
                  stroke="var(--color-border-subtle)"
                  strokeDasharray="2,3"
                />
                <text
                  x={x}
                  y={height - padding.bottom + 18}
                  fill="var(--color-text-muted)"
                  fontSize="10"
                  fontFamily="var(--font-mono)"
                  textAnchor="middle"
                >
                  {val.toFixed(0)} ms
                </text>
              </g>
            );
          })}

          {/* Row Labels */}
          <text
            x={padding.left - 12}
            y={hitY + 4}
            fill="var(--color-primary)"
            fontSize="12"
            fontFamily="var(--font-mono)"
            fontWeight="600"
            textAnchor="end"
          >
            HIT
          </text>
          <text
            x={padding.left - 12}
            y={missY + 4}
            fill="var(--color-accent)"
            fontSize="12"
            fontFamily="var(--font-mono)"
            fontWeight="600"
            textAnchor="end"
          >
            MISS
          </text>

          {/* Guide baseline */}
          <line
            x1={padding.left}
            y1={hitY}
            x2={width - padding.right}
            y2={hitY}
            stroke="var(--color-border-subtle)"
          />
          <line
            x1={padding.left}
            y1={missY}
            x2={width - padding.right}
            y2={missY}
            stroke="var(--color-border-subtle)"
          />

          {/* HIT sample dots */}
          {hitPoints.map((pt, i) => (
            <circle
              key={`hit-${i}`}
              cx={scaleX(pt.val)}
              cy={hitY + pt.jitter}
              r="3.5"
              fill="var(--color-primary)"
              opacity="0.65"
            >
              <title>{`HIT: ${pt.val.toFixed(2)} ms`}</title>
            </circle>
          ))}

          {/* MISS sample dots */}
          {missPoints.map((pt, i) => (
            <circle
              key={`miss-${i}`}
              cx={scaleX(pt.val)}
              cy={missY + pt.jitter}
              r="3.5"
              fill="var(--color-accent)"
              opacity="0.65"
            >
              <title>{`MISS: ${pt.val.toFixed(2)} ms`}</title>
            </circle>
          ))}

          {/* HIT Median marker */}
          <g>
            <line
              x1={scaleX(stats.median_hit_ms)}
              y1={hitY - 14}
              x2={scaleX(stats.median_hit_ms)}
              y2={hitY + 14}
              stroke="var(--color-primary)"
              strokeWidth="2.5"
            />
            <text
              x={scaleX(stats.median_hit_ms)}
              y={hitY - 18}
              fill="var(--color-primary)"
              fontSize="10"
              fontFamily="var(--font-mono)"
              fontWeight="700"
              textAnchor="middle"
            >
              {stats.median_hit_ms.toFixed(1)} ms
            </text>
          </g>

          {/* MISS Median marker */}
          <g>
            <line
              x1={scaleX(stats.median_miss_ms)}
              y1={missY - 14}
              x2={scaleX(stats.median_miss_ms)}
              y2={missY + 14}
              stroke="var(--color-accent)"
              strokeWidth="2.5"
            />
            <text
              x={scaleX(stats.median_miss_ms)}
              y={missY + 26}
              fill="var(--color-accent)"
              fontSize="10"
              fontFamily="var(--font-mono)"
              fontWeight="700"
              textAnchor="middle"
            >
              {stats.median_miss_ms.toFixed(1)} ms
            </text>
          </g>
        </svg>
      </div>

      {/* Metrics Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))',
          gap: 'var(--space-2)',
          borderTop: '1px solid var(--color-border-subtle)',
          paddingTop: 'var(--space-3)',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
            MEDIAN DELTA (Δ)
          </span>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-sm)',
              fontWeight: 700,
              color: isLeak ? 'var(--color-danger)' : 'var(--color-text-primary)',
            }}
          >
            {stats.median_diff_ms.toFixed(2)} ms
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
            P-VALUE (U TEST)
          </span>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-sm)',
              fontWeight: 700,
              color: stats.p_value < 0.01 ? 'var(--color-danger)' : 'var(--color-text-primary)',
            }}
          >
            {stats.p_value < 0.0001 ? '< 0.0001' : stats.p_value.toFixed(4)}
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
            ROC AUC
          </span>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-sm)',
              fontWeight: 700,
              color: stats.auc > 0.75 ? 'var(--color-danger)' : 'var(--color-text-primary)',
            }}
          >
            {stats.auc.toFixed(3)}
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
            MEAN HIT / MISS
          </span>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              color: 'var(--color-text-secondary)',
            }}
          >
            {stats.mean_hit_ms.toFixed(1)} / {stats.mean_miss_ms.toFixed(1)} ms
          </span>
        </div>
      </div>
    </div>
  );
};
