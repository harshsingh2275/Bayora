import React, { useEffect, useState, useMemo } from 'react';
import { apiClient } from '../api/client';
import type { BreakitReportResponse, BreakitProbe, ViewType } from '../types/api';

interface BreakitViewProps {
  onNavigate?: (view: ViewType) => void;
}

// ── Category color map ────────────────────────────────────────────────────────

function categoryStyle(cat: string): { color: string; bg: string } {
  const map: Record<string, { color: string; bg: string }> = {
    Network:       { color: 'var(--accent-blue-team)', bg: 'var(--accent-blue-bg)' },
    Filesystem:    { color: 'var(--accent-gateway)', bg: 'var(--accent-gateway-bg)' },
    Privilege:     { color: 'var(--accent-red-team)', bg: 'var(--accent-red-bg)' },
    Authorization: { color: 'var(--status-warn-text)', bg: 'var(--status-warn-bg)' },
    Log:           { color: 'var(--status-pass-text)', bg: 'var(--status-pass-bg)' },
    Config:        { color: 'var(--text-secondary)', bg: 'var(--bg-subtle)' },
  };
  return map[cat] ?? { color: 'var(--text-muted)', bg: 'var(--bg-subtle)' };
}

// ── Refresh icon ──────────────────────────────────────────────────────────────

const RefreshIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M2.5 8A5.5 5.5 0 0 1 8 2.5c2.1 0 3.94 1.19 4.87 2.93" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    <path d="M13.5 8A5.5 5.5 0 0 1 8 13.5c-2.1 0-3.94-1.19-4.87-2.93" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    <path d="M11.5 2.5L13.37 5.37 10.5 4.2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    <path d="M4.5 13.5L2.63 10.63 5.5 11.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

// ── Probe row ─────────────────────────────────────────────────────────────────

const ProbeRow: React.FC<{ probe: BreakitProbe }> = ({ probe }) => {
  const cs = categoryStyle(probe.category);
  const hasDetails = probe.observed && probe.observed.length > 80;

  return (
    <tr>
      <td style={{ whiteSpace: 'nowrap' }}>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '2px 8px',
            borderRadius: 'var(--radius-sm)',
            background: cs.bg,
            color: cs.color,
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
            border: `1px solid ${cs.color}30`,
            whiteSpace: 'nowrap',
          }}
        >
          {probe.category}
        </span>
      </td>
      <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-primary)' }}>
        {probe.id}
      </td>
      <td style={{ minWidth: 240 }}>
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {probe.description}
        </span>
      </td>
      <td style={{ whiteSpace: 'nowrap' }}>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            padding: '2px 8px',
            borderRadius: 'var(--radius-sm)',
            background: probe.passed ? 'var(--status-pass-bg)' : 'var(--status-fail-bg)',
            color: probe.passed ? 'var(--status-pass-text)' : 'var(--status-fail-text)',
            border: `1px solid ${probe.passed ? 'var(--status-pass-border)' : 'var(--status-fail-border)'}`,
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-xs)',
            fontWeight: 700,
            whiteSpace: 'nowrap',
          }}
        >
          {probe.passed ? '✓ PASS' : '✕ FAIL'}
        </span>
      </td>
      <td style={{ minWidth: 240 }}>
        {hasDetails ? (
          <details className="mono-chip">
            <summary>{probe.observed.slice(0, 60)}…</summary>
            <pre>{probe.observed}</pre>
          </details>
        ) : (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            {probe.observed || '—'}
          </span>
        )}
      </td>
    </tr>
  );
};

// ── Main view ─────────────────────────────────────────────────────────────────

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

  useEffect(() => { fetchReport(); }, []);

  const categories = useMemo(() => {
    if (!report?.probes) return ['All'];
    const cats = new Set(report.probes.map(p => p.category));
    return ['All', ...Array.from(cats)];
  }, [report]);

  const filteredProbes = useMemo(() => {
    if (!report?.probes) return [];
    if (selectedCategory === 'All') return report.probes;
    return report.probes.filter(p => p.category === selectedCategory);
  }, [report, selectedCategory]);

  const passed = report?.summary?.passed ?? 0;
  const total  = report?.summary?.total  ?? 0;
  const failed = report?.summary?.failed ?? 0;

  return (
    <div style={{ paddingBottom: '6rem' }}>
      <div className="container" style={{ paddingTop: '2.5rem' }}>

        {/* ── Header ───────────────────────────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: 'var(--space-4)',
            marginBottom: 'var(--space-8)',
            paddingBottom: 'var(--space-6)',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        >
          <div>
            <div className="section-overline">Empirical Security Verification</div>
            <h1
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: 'var(--text-h1)',
                fontWeight: 400,
                color: 'var(--text-primary)',
                margin: '0 0 var(--space-2) 0',
              }}
            >
              Active Isolation Probes
            </h1>
            <p style={{ fontSize: 'var(--text-body)', color: 'var(--text-secondary)', maxWidth: '640px', margin: 0 }}>
              Automated break-it harness executes negative-security probes from within tenant containers and
              from the host. Every probe must demonstrate that the isolation control blocks what it claims.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={fetchReport}
            disabled={loading}
            aria-label="Refresh break-it report"
          >
            <RefreshIcon /> {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>

        {/* ── KPI cards ────────────────────────────────────────────────────── */}
        <div className="kpi-grid" style={{ marginBottom: 'var(--space-8)' }}>
          <div className="kpi-card">
            <div className="kpi-card__label">Probes Executed</div>
            <div className="kpi-card__value">{loading ? '…' : total}</div>
          </div>
          <div
            className="kpi-card"
            style={{ borderLeft: `3px solid ${failed === 0 ? 'var(--status-pass-text)' : 'var(--status-fail-text)'}` }}
          >
            <div className="kpi-card__label">Passed</div>
            <div className="kpi-card__value" style={{ color: failed === 0 ? 'var(--status-pass-text)' : 'var(--text-primary)' }}>
              {loading ? '…' : passed}
            </div>
            {passed === total && total > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--status-pass-text)', animation: 'pulse-dot 2s ease-in-out infinite', display: 'inline-block' }} />
                <span className="kpi-card__sub">All controls holding</span>
              </div>
            )}
          </div>
          <div
            className="kpi-card"
            style={{ borderLeft: `3px solid ${failed > 0 ? 'var(--status-fail-text)' : 'var(--border-subtle)'}` }}
          >
            <div className="kpi-card__label">Failed</div>
            <div className="kpi-card__value" style={{ color: failed > 0 ? 'var(--status-fail-text)' : 'var(--text-muted)' }}>
              {loading ? '…' : failed}
            </div>
          </div>
          <div className="kpi-card">
            <div className="kpi-card__label">Report Generated</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginTop: 4 }}>
              {report?.generated_at ? new Date(report.generated_at).toLocaleString() : '—'}
            </div>
            {report?.git_commit && (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>
                {report.git_commit.slice(0, 10)}
              </div>
            )}
          </div>
        </div>

        {/* ── Error ────────────────────────────────────────────────────────── */}
        {error && (
          <div
            style={{
              marginBottom: 'var(--space-5)',
              padding: 'var(--space-3) var(--space-4)',
              background: 'var(--status-fail-bg)',
              border: '1px solid var(--status-fail-border)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--status-fail-text)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
            }}
          >
            {error}
          </div>
        )}

        {/* ── Category filter pills ─────────────────────────────────────────── */}
        <div className="filter-pills" style={{ marginBottom: 'var(--space-4)' }}>
          {categories.map(cat => (
            <button
              key={cat}
              type="button"
              className={`filter-pill${selectedCategory === cat ? ' active' : ''}`}
              onClick={() => setSelectedCategory(cat)}
            >
              {cat}
              {cat !== 'All' && report ? (
                <span style={{ marginLeft: 4, opacity: 0.7 }}>
                  ({report.probes.filter(p => p.category === cat && p.passed).length}/
                  {report.probes.filter(p => p.category === cat).length})
                </span>
              ) : null}
            </button>
          ))}
        </div>

        {/* ── Probes table ──────────────────────────────────────────────────── */}
        <div className="table-scroll-container">
          <table>
            <thead>
              <tr>
                <th style={{ whiteSpace: 'nowrap' }}>Category</th>
                <th style={{ whiteSpace: 'nowrap' }}>Probe ID</th>
                <th style={{ minWidth: 240 }}>Adversarial Action / Description</th>
                <th style={{ whiteSpace: 'nowrap' }}>Status</th>
                <th style={{ minWidth: 240 }}>Observed Output</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--space-8)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                    Loading probe report…
                  </td>
                </tr>
              )}
              {!loading && filteredProbes.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--space-8)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                    No probe report available yet. Run the break-it harness via <code>make breakit</code>.
                  </td>
                </tr>
              )}
              {filteredProbes.map(probe => (
                <ProbeRow key={probe.id} probe={probe} />
              ))}
            </tbody>
          </table>
        </div>

        {/* ── Methodology note ──────────────────────────────────────────────── */}
        <div
          style={{
            marginTop: 'var(--space-7)',
            padding: 'var(--space-5) var(--space-6)',
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 'var(--space-2)' }}>
            Probe Methodology
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--space-3)' }}>
            {[
              { cat: 'Network', desc: 'DNS resolution + TCP connect to cross-tenant IPs, model, logger, verifier, internet (N1–N4)' },
              { cat: 'Filesystem', desc: 'Access to other tenant data, log volume, docker.sock; write to read-only root (F1–F3)' },
              { cat: 'Privilege', desc: 'Effective UID, CapEff bitmask, NoNewPrivs flag, Seccomp filter active (P1–P5)' },
              { cat: 'Authorization', desc: 'Bad tokens, role swaps, sealed-data access, digest mismatch (A1–A8)' },
              { cat: 'Log', desc: 'Tamper detection demo: modify, delete, reorder, forge, truncate (L1–L3)' },
              { cat: 'Config', desc: 'Compose hardening: privileged, host-net, pid, devices, sock, limits, networks (C1–C6)' },
            ].map(({ cat, desc }) => {
              const cs = categoryStyle(cat);
              return (
                <div key={cat} style={{ display: 'flex', gap: 'var(--space-2)' }}>
                  <span
                    style={{
                      flexShrink: 0,
                      display: 'inline-flex',
                      alignItems: 'center',
                      padding: '2px 8px',
                      height: 20,
                      borderRadius: 'var(--radius-sm)',
                      background: cs.bg,
                      color: cs.color,
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      border: `1px solid ${cs.color}30`,
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {cat}
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{desc}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
