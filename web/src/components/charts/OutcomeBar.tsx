import React from 'react';

interface OutcomeBarProps {
  aggregate: {
    blocked_input: number;
    blocked_output: number;
    refused: number;
    complied: number;
    error: number;
  };
  total: number;
  asr?: number;
}

export const OutcomeBar: React.FC<OutcomeBarProps> = ({ aggregate, total, asr }) => {
  if (total === 0) {
    return (
      <div
        style={{
          padding: 'var(--space-3)',
          border: '1px solid var(--color-border-subtle)',
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-xs)',
          color: 'var(--color-text-muted)',
          textAlign: 'center',
        }}
      >
        No evaluated attacks recorded
      </div>
    );
  }

  const segments = [
    {
      key: 'blocked_input',
      label: 'Blocked (Input)',
      count: aggregate.blocked_input,
      color: 'var(--color-primary)',
      bg: 'var(--color-primary-soft)',
    },
    {
      key: 'blocked_output',
      label: 'Blocked (Output)',
      count: aggregate.blocked_output,
      color: 'var(--color-accent)',
      bg: 'var(--color-accent-soft)',
    },
    {
      key: 'refused',
      label: 'Refused',
      count: aggregate.refused,
      color: 'var(--color-text-secondary)',
      bg: 'var(--color-bg-hover)',
    },
    {
      key: 'complied',
      label: 'Complied (Breach)',
      count: aggregate.complied,
      color: 'var(--color-danger)',
      bg: 'var(--color-danger-soft)',
    },
    {
      key: 'error',
      label: 'Error',
      count: aggregate.error,
      color: 'var(--color-warning)',
      bg: 'var(--color-warning-soft)',
    },
  ];

  const calculatedAsr =
    asr !== undefined ? asr : total > 0 ? aggregate.complied / total : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      {/* Header with Total and ASR */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-xs)',
        }}
      >
        <div>
          <span style={{ color: 'var(--color-text-muted)' }}>Evaluated Items: </span>
          <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
            {total}
          </span>
        </div>
        <div>
          <span style={{ color: 'var(--color-text-muted)' }}>Attack Success Rate (ASR): </span>
          <span
            style={{
              fontWeight: 700,
              color: calculatedAsr > 0 ? 'var(--color-danger)' : 'var(--color-primary)',
            }}
          >
            {(calculatedAsr * 100).toFixed(1)}%
          </span>
        </div>
      </div>

      {/* Stacked Bar with 0px radius */}
      <div
        style={{
          display: 'flex',
          height: '24px',
          width: '100%',
          border: '1px solid var(--color-border-subtle)',
          overflow: 'hidden',
          backgroundColor: 'var(--color-bg-surface)',
        }}
        role="progressbar"
        aria-label="Attack outcome distribution"
      >
        {segments.map((seg) => {
          const pct = (seg.count / total) * 100;
          if (pct === 0) return null;
          return (
            <div
              key={seg.key}
              title={`${seg.label}: ${seg.count} (${pct.toFixed(1)}%)`}
              style={{
                width: `${pct}%`,
                backgroundColor: seg.color,
                height: '100%',
                borderRight: '1px solid var(--color-bg-base)',
                transition: 'width 0.3s ease',
              }}
            />
          );
        })}
      </div>

      {/* Legend Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: 'var(--space-2)',
        }}
      >
        {segments.map((seg) => {
          const pct = total > 0 ? ((seg.count / total) * 100).toFixed(1) : '0.0';
          return (
            <div
              key={seg.key}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                padding: '4px 6px',
                border: '1px solid var(--color-border-subtle)',
                backgroundColor: 'var(--color-bg-surface)',
                fontSize: 'var(--text-xs)',
              }}
            >
              <span
                style={{
                  width: '10px',
                  height: '10px',
                  backgroundColor: seg.color,
                  flexShrink: 0,
                  display: 'inline-block',
                }}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    color: 'var(--color-text-secondary)',
                    fontFamily: 'var(--font-sans)',
                    fontSize: '11px',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {seg.label}
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 600,
                    color: 'var(--color-text-primary)',
                  }}
                >
                  {seg.count}{' '}
                  <span style={{ fontWeight: 400, color: 'var(--color-text-muted)' }}>
                    ({pct}%)
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
