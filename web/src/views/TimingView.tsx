import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from '../api/client';
import type { TimingReportResponse, TimingModeStats, ViewType } from '../types/api';
import { useAuth } from '../context/AuthContext';
import { TimingChart } from '../components/charts/TimingChart';

interface TimingViewProps {
  onNavigate?: (view: ViewType) => void;
}

// ── Mode stats card ───────────────────────────────────────────────────────────

interface ModeCardProps {
  title: string;
  mode: 'isolated' | 'shared';
  stats: TimingModeStats | undefined;
  samples?: { hit: number[]; miss: number[] };
  isCurrent: boolean;
  isAuthenticated: boolean;
  onToggle: () => void;
  switchingMode: boolean;
}

const ModeCard: React.FC<ModeCardProps> = ({ title, mode, stats, samples, isCurrent, isAuthenticated, onToggle, switchingMode }) => {
  const isIsolated = mode === 'isolated';
  const leakDetected = stats?.verdict === 'leak_detected';
  const borderColor = isIsolated
    ? 'var(--accent-primary)'
    : leakDetected ? 'var(--status-fail-text)' : 'var(--status-warn-text)';

  return (
    <div
      style={{
        background: 'var(--bg-surface)',
        border: `1px solid var(--border-subtle)`,
        borderTop: `3px solid ${borderColor}`,
        borderRadius: 'var(--radius-md)',
        boxShadow: 'var(--shadow-card)',
        overflow: 'hidden',
      }}
    >
      {/* Card header */}
      <div
        style={{
          padding: 'var(--space-5) var(--space-6)',
          borderBottom: '1px solid var(--border-subtle)',
          background: isIsolated ? 'rgba(46,74,54,0.04)' : 'rgba(180,35,24,0.04)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 'var(--space-3)',
        }}
      >
        <div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: borderColor,
              fontWeight: 700,
              marginBottom: 4,
            }}
          >
            {isIsolated ? 'ISOLATED CACHE MODE' : 'SHARED CACHE MODE'}
          </div>
          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: '1.15rem',
              fontWeight: 400,
              color: 'var(--text-primary)',
            }}
          >
            {title}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          {stats && (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                padding: '3px 10px',
                borderRadius: 'var(--radius-pill)',
                background: stats.verdict === 'no_leak_detected' ? 'var(--status-pass-bg)' : 'var(--status-fail-bg)',
                color: stats.verdict === 'no_leak_detected' ? 'var(--status-pass-text)' : 'var(--status-fail-text)',
                border: `1px solid ${stats.verdict === 'no_leak_detected' ? 'var(--status-pass-border)' : 'var(--status-fail-border)'}`,
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 700,
                whiteSpace: 'nowrap',
              }}
            >
              {stats.verdict === 'no_leak_detected' ? '✓ No Leak Detected' : '✕ Leak Detected'}
            </span>
          )}
          {isCurrent && (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                padding: '2px 8px',
                borderRadius: 'var(--radius-pill)',
                background: 'rgba(46,74,54,0.1)',
                border: '1px solid var(--accent-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.67rem',
                color: 'var(--accent-primary)',
                fontWeight: 600,
              }}
            >
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--accent-primary)', animation: 'pulse-dot 2s ease-in-out infinite', display: 'inline-block' }} />
              Active
            </span>
          )}
        </div>
      </div>

      {/* Stats grid */}
      {stats ? (
        <div style={{ padding: 'var(--space-5) var(--space-6)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-4)', marginBottom: 'var(--space-5)' }}>
            {[
              { label: 'p-value (Mann-Whitney U)', value: stats.p_value?.toFixed(4), highlight: stats.p_value < 0.01 ? 'fail' : 'pass' },
              { label: 'AUC (ROC)', value: stats.auc?.toFixed(3), highlight: stats.auc > 0.8 ? 'fail' : 'pass' },
              { label: 'Median Δ (ms)', value: stats.median_diff_ms?.toFixed(1) + 'ms' },
            ].map(({ label, value, highlight }) => (
              <div
                key={label}
                style={{
                  background: 'var(--bg-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: 'var(--space-3)',
                  textAlign: 'center',
                }}
              >
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '1.1rem',
                    fontWeight: 700,
                    color: highlight === 'fail' ? 'var(--status-fail-text)' : highlight === 'pass' ? 'var(--status-pass-text)' : 'var(--text-primary)',
                  }}
                >
                  {value ?? '—'}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-muted)', marginTop: 2, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {label}
                </div>
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-5)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
            <div>
              <span style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>HIT</span> (shared prefix) — median: {stats.median_hit_ms?.toFixed(1)}ms · n={stats.n_hit}
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>MISS</span> (fresh prefix) — median: {stats.median_miss_ms?.toFixed(1)}ms · n={stats.n_miss}
            </div>
          </div>

          {/* Timing chart */}
          {samples && (
            <TimingChart
              title={`${isIsolated ? 'Isolated' : 'Shared'} mode latency distribution`}
              mode={mode}
              stats={stats}
              samples={samples}
            />
          )}
        </div>
      ) : (
        <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
          No {mode} mode data in report.
        </div>
      )}

      {/* Operator toggle footer */}
      {isAuthenticated && !isCurrent && (
        <div style={{ padding: 'var(--space-3) var(--space-5)', borderTop: '1px solid var(--border-subtle)', background: 'var(--bg-subtle)', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onToggle}
            disabled={switchingMode}
          >
            {switchingMode ? 'Switching…' : `Switch to ${mode} mode`}
          </button>
        </div>
      )}
    </div>
  );
};

// ── Main view ─────────────────────────────────────────────────────────────────

export const TimingView: React.FC<TimingViewProps> = () => {
  const { adminToken, isAuthenticated } = useAuth();
  const [report, setReport] = useState<TimingReportResponse | null>(null);
  const [currentMode, setCurrentMode] = useState<'isolated' | 'shared' | null>(null);
  const [loading, setLoading] = useState(true);
  const [switchingMode, setSwitchingMode] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchTimingData = useCallback(async () => {
    try {
      setLoading(true);
      const [rep, modeRes] = await Promise.allSettled([
        apiClient.getTimingReport(),
        apiClient.getCacheMode(),
      ]);
      if (rep.status === 'fulfilled') setReport(rep.value);
      if (modeRes.status === 'fulfilled') setCurrentMode(modeRes.value.mode);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load timing data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchTimingData(); }, [fetchTimingData]);

  const handleToggle = async (newMode: 'isolated' | 'shared') => {
    if (!adminToken) return;
    setSwitchingMode(true);
    try {
      const res = await apiClient.setCacheMode(newMode, adminToken);
      setCurrentMode(res.mode);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to switch cache mode');
    } finally {
      setSwitchingMode(false);
    }
  };

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
            <div className="section-overline">Microarchitectural Isolation</div>
            <h1
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: 'var(--text-h1)',
                fontWeight: 400,
                color: 'var(--text-primary)',
                margin: '0 0 var(--space-2) 0',
              }}
            >
              Timing Side-Channel Analysis
            </h1>
            <p style={{ fontSize: 'var(--text-body)', color: 'var(--text-secondary)', maxWidth: '640px', margin: 0 }}>
              Prompt-prefix caching in shared LLM engines can leak prior tenant prompt contents via
              sub-millisecond latency variations. Bayora measures the side channel empirically and proves
              that isolated cache mode eliminates statistical distinguishability.
            </p>
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={fetchTimingData} disabled={loading}>
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>

        {/* ── Error ────────────────────────────────────────────────────────── */}
        {error && (
          <div style={{ marginBottom: 'var(--space-5)', padding: 'var(--space-3) var(--space-4)', background: 'var(--status-fail-bg)', border: '1px solid var(--status-fail-border)', borderRadius: 'var(--radius-sm)', color: 'var(--status-fail-text)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
            {error}
          </div>
        )}

        {/* ── Active mode indicator ─────────────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-4)',
            padding: 'var(--space-4) var(--space-5)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            marginBottom: 'var(--space-6)',
            flexWrap: 'wrap',
          }}
        >
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
              Active Gateway Cache Mode
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              {currentMode && (
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: currentMode === 'isolated' ? 'var(--status-pass-text)' : 'var(--status-warn-text)', animation: 'pulse-dot 2s ease-in-out infinite', display: 'inline-block' }} />
              )}
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '1rem', fontWeight: 700, color: currentMode === 'isolated' ? 'var(--accent-primary)' : 'var(--status-warn-text)', textTransform: 'uppercase' }}>
                {currentMode ? currentMode : 'Loading…'}
              </span>
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                {currentMode === 'isolated' ? '— tenant isolation active (default defense)' : '— shared prefix cache (vulnerability baseline)'}
              </span>
            </div>
          </div>
          {!isAuthenticated && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginLeft: 'auto' }}>
              Operator token required to toggle
            </span>
          )}
        </div>

        {/* ── Decision rule ─────────────────────────────────────────────────── */}
        {report?.verdict_rule && (
          <div
            style={{
              padding: 'var(--space-4) var(--space-5)',
              background: 'rgba(46,74,54,0.06)',
              border: '1px solid var(--accent-primary)',
              borderRadius: 'var(--radius-md)',
              marginBottom: 'var(--space-7)',
            }}
          >
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--accent-primary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
              Pre-Registered Decision Rule (Architecture §9)
            </div>
            <p style={{ fontFamily: 'var(--font-sans)', fontSize: 'var(--text-sm)', color: 'var(--text-primary)', margin: 0, lineHeight: 1.55 }}>
              {report.verdict_rule}
            </p>
          </div>
        )}

        {/* ── 2-column comparison grid ──────────────────────────────────────── */}
        <div className="compare-grid" style={{ marginBottom: 'var(--space-8)' }}>
          <ModeCard
            title="Isolated Cache Mode (Enforced Defense)"
            mode="isolated"
            stats={report?.modes?.isolated}
            samples={report?.raw_samples?.isolated}
            isCurrent={currentMode === 'isolated'}
            isAuthenticated={isAuthenticated}
            onToggle={() => handleToggle('isolated')}
            switchingMode={switchingMode}
          />
          <ModeCard
            title="Shared Cache Mode (Vulnerability Baseline)"
            mode="shared"
            stats={report?.modes?.shared}
            samples={report?.raw_samples?.shared}
            isCurrent={currentMode === 'shared'}
            isAuthenticated={isAuthenticated}
            onToggle={() => handleToggle('shared')}
            switchingMode={switchingMode}
          />
        </div>

        {/* ── Loading placeholder ───────────────────────────────────────────── */}
        {loading && !report && (
          <div style={{ textAlign: 'center', padding: 'var(--space-12)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
            Loading timing experiment data…
          </div>
        )}

        {/* ── No data state ─────────────────────────────────────────────────── */}
        {!loading && !report && (
          <div style={{ textAlign: 'center', padding: 'var(--space-12)', color: 'var(--text-muted)' }}>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', margin: '0 0 var(--space-3) 0' }}>
              No timing experiment data available yet.
            </p>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Run the experiment from the host: <code>make timing</code>
            </p>
          </div>
        )}

        {/* ── Protocol metadata ─────────────────────────────────────────────── */}
        {report && (
          <div className="compare-grid">
            <div className="card">
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                Benchmark Environment
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                <div>Model: {String(report.environment?.model_file || 'Qwen2.5-0.5B-Instruct')}</div>
                <div>Platform: {String(report.environment?.platform || 'Linux')}</div>
                <div>Engine: llama.cpp {String(report.environment?.llamacpp_version || '—')}</div>
                <div>Trials/condition: {String(report.protocol?.n_trials_per_condition || '—')}</div>
                <div>Prefix words: {String(report.protocol?.prefix_words || '—')}</div>
                <div>Generated: {report.generated_at ? new Date(report.generated_at).toLocaleString() : '—'}</div>
              </div>
            </div>
            <div className="card" style={{ background: 'var(--status-warn-bg)', border: '1px solid var(--status-warn-border)' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--status-warn-text)', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                Documented Limitations
              </div>
              <ul style={{ margin: 0, paddingLeft: 'var(--space-4)', fontFamily: 'var(--font-sans)', fontSize: 'var(--text-xs)', color: 'var(--status-warn-text)', lineHeight: 1.55, display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {(report.limitations || []).map((lim, i) => (
                  <li key={i}>{lim}</li>
                ))}
                {(!report.limitations || report.limitations.length === 0) && (
                  <li>Measured from host through localhost; shared CPU contention is an unmitigated timing channel.</li>
                )}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
