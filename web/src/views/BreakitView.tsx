import React, { useEffect, useState, useMemo } from 'react';
import { apiClient } from '../api/client';
import type { BreakitReportResponse, ViewType } from '../types/api';
import { StatusBadge } from '../components/common/StatusBadge';
import { RefreshCwIcon } from '../components/common/Icons';

interface BreakitViewProps {
  onNavigate?: (view: ViewType) => void;
}

export const BreakitView: React.FC<BreakitViewProps> = () => {
  const [report, setReport] = useState<BreakitReportResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('All');

  const fetchReport = async () => {
    try {
      setLoading(true);
      const data = await apiClient.getBreakitReport();
      setReport(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load isolation probe report');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const categories = useMemo(() => {
    if (!report?.probes) return ['All'];
    const cats = new Set(report.probes.map((p) => p.category));
    return ['All', ...Array.from(cats)];
  }, [report]);

  const filteredProbes = useMemo(() => {
    if (!report?.probes) return [];
    if (selectedCategory === 'All') return report.probes;
    return report.probes.filter((p) => p.category === selectedCategory);
  }, [report, selectedCategory]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
      {/* View Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: 'var(--space-4)',
          borderBottom: '1px solid var(--color-border-subtle)',
          paddingBottom: 'var(--space-6)',
        }}
      >
        <div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: 'var(--color-primary)',
              marginBottom: 'var(--space-2)',
            }}
          >
            Empirical Security Verification
          </div>
          <h1
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: 'var(--text-3xl)',
              fontWeight: 400,
              color: 'var(--color-text-primary)',
              margin: '0 0 var(--space-2) 0',
            }}
          >
            Active Isolation Probes
          </h1>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              color: 'var(--color-text-secondary)',
              maxWidth: '720px',
              margin: 0,
            }}
          >
            Security properties must actively fail when violated. This test suite executes
            negative probes directly from inside untrusted tenant containers to confirm that
            network, capability, filesystem, and authorization boundaries hold.
          </p>
        </div>

        <button
          type="button"
          onClick={fetchReport}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 'var(--space-2)',
            backgroundColor: 'var(--color-bg-surface)',
            color: 'var(--color-text-secondary)',
            border: '1px solid var(--color-border-subtle)',
            padding: 'var(--space-2) var(--space-3)',
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-xs)',
            cursor: 'pointer',
          }}
        >
          <RefreshCwIcon size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div
          style={{
            padding: 'var(--space-4)',
            backgroundColor: 'var(--color-danger-soft)',
            border: '1px solid var(--color-danger)',
            color: 'var(--color-danger)',
            fontSize: 'var(--text-sm)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {error}
        </div>
      )}

      {/* Summary Scorecard */}
      <div
        style={{
          border: '1px solid var(--color-border-subtle)',
          backgroundColor: 'var(--color-bg-surface)',
          padding: 'var(--space-5)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 'var(--space-4)',
        }}
      >
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            PROBES EXECUTED
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-2xl)',
              fontWeight: 700,
              color: 'var(--color-text-primary)',
              marginTop: '2px',
            }}
          >
            {report?.summary?.total ?? 0}
          </div>
        </div>

        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            PASSED (BLOCKED PROBES)
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-2xl)',
              fontWeight: 700,
              color: 'var(--color-primary)',
              marginTop: '2px',
            }}
          >
            {report?.summary?.passed ?? 0}
          </div>
        </div>

        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            FAILED (BREACHES OBSERVED)
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-2xl)',
              fontWeight: 700,
              color: report?.summary?.failed === 0 ? 'var(--color-text-muted)' : 'var(--color-danger)',
              marginTop: '2px',
            }}
          >
            {report?.summary?.failed ?? 0}
          </div>
        </div>

        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            EXECUTION TIMESTAMP & COMMIT
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              color: 'var(--color-text-secondary)',
              marginTop: '4px',
            }}
          >
            {report?.generated_at ? new Date(report.generated_at).toLocaleString() : '-'}
            <div style={{ color: 'var(--color-text-muted)', marginTop: '2px' }}>
              Commit: {report?.git_commit ? report.git_commit.slice(0, 8) : 'latest'}
            </div>
          </div>
        </div>
      </div>

      {/* Category Filter Pills */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        {categories.map((cat) => (
          <button
            key={cat}
            type="button"
            onClick={() => setSelectedCategory(cat)}
            style={{
              padding: '4px 10px',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              border: '1px solid var(--color-border-subtle)',
              backgroundColor:
                selectedCategory === cat
                  ? 'var(--color-primary)'
                  : 'var(--color-bg-surface)',
              color:
                selectedCategory === cat
                  ? 'var(--color-text-inverse)'
                  : 'var(--color-text-secondary)',
              cursor: 'pointer',
            }}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Probes Table */}
      <div
        style={{
          border: '1px solid var(--color-border-subtle)',
          backgroundColor: 'var(--color-bg-surface)',
          overflowX: 'auto',
        }}
      >
        <div
          style={{
            padding: 'var(--space-3) var(--space-4)',
            borderBottom: '1px solid var(--color-border-subtle)',
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            color: 'var(--color-text-muted)',
            display: 'flex',
            justifyContent: 'space-between',
          }}
        >
          <span>Active Probe Records ({filteredProbes.length})</span>
          <span>Zero Tolerated Failures</span>
        </div>

        {loading && !report ? (
          <div
            style={{
              padding: 'var(--space-8)',
              textAlign: 'center',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-muted)',
            }}
          >
            Loading isolation probes...
          </div>
        ) : filteredProbes.length === 0 ? (
          <div
            style={{
              padding: 'var(--space-8)',
              textAlign: 'center',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-muted)',
            }}
          >
            No probes found in this category.
          </div>
        ) : (
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              fontSize: 'var(--text-xs)',
              textAlign: 'left',
            }}
          >
            <thead>
              <tr
                style={{
                  backgroundColor: 'var(--color-bg-base)',
                  borderBottom: '1px solid var(--color-border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-text-muted)',
                }}
              >
                <th style={{ padding: '8px 12px' }}>Category</th>
                <th style={{ padding: '8px 12px' }}>Probe ID</th>
                <th style={{ padding: '8px 12px' }}>Adversarial Action & Description</th>
                <th style={{ padding: '8px 12px' }}>Expected Enforcement</th>
                <th style={{ padding: '8px 12px' }}>Observed</th>
                <th style={{ padding: '8px 12px', textAlign: 'right' }}>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {filteredProbes.map((probe) => (
                <tr
                  key={probe.id}
                  style={{
                    borderBottom: '1px solid var(--color-border-subtle)',
                  }}
                >
                  <td style={{ padding: '10px 12px' }}>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        padding: '2px 6px',
                        border: '1px solid var(--color-border-subtle)',
                        backgroundColor: 'var(--color-bg-base)',
                        fontSize: '11px',
                      }}
                    >
                      {probe.category}
                    </span>
                  </td>
                  <td
                    style={{
                      padding: '10px 12px',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      color: 'var(--color-text-primary)',
                    }}
                  >
                    {probe.id}
                  </td>
                  <td
                    style={{
                      padding: '10px 12px',
                      fontFamily: 'var(--font-sans)',
                      color: 'var(--color-text-secondary)',
                      maxWidth: '320px',
                    }}
                  >
                    {probe.description}
                  </td>
                  <td
                    style={{
                      padding: '10px 12px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-primary)',
                      fontSize: '11px',
                    }}
                  >
                    {probe.expected}
                  </td>
                  <td
                    style={{
                      padding: '10px 12px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-text-secondary)',
                      fontSize: '11px',
                    }}
                  >
                    {probe.observed}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                    <StatusBadge status={probe.passed ? 'verified' : 'failed'} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
