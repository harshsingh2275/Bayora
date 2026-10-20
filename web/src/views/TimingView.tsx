import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from '../api/client';
import type { TimingReportResponse, ViewType } from '../types/api';
import { useAuth } from '../context/AuthContext';
import { TimingChart } from '../components/charts/TimingChart';
import { RefreshCwIcon } from '../components/common/Icons';

interface TimingViewProps {
  onNavigate?: (view: ViewType) => void;
}

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
      setError(err instanceof Error ? err.message : 'Failed to fetch timing experiment data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTimingData();
  }, [fetchTimingData]);

  const handleToggleCacheMode = async (newMode: 'isolated' | 'shared') => {
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
            Microarchitectural Isolation
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
            Timing Side-Channel Analysis
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
            Prompt-prefix caching in shared LLM engines can leak prior tenant prompt contents
            via sub-millisecond response latency variations. Bayora proves that isolated cache
            mode eliminates statistical distinguishability between cache hits and misses.
          </p>
        </div>

        <button
          type="button"
          onClick={fetchTimingData}
          disabled={loading}
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
            cursor: loading ? 'default' : 'pointer',
            opacity: loading ? 0.6 : 1,
          }}
        >
          <RefreshCwIcon size={14} />
          <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
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

      {/* Gateway Runtime Cache Mode Controller */}
      <div
        style={{
          border: '1px solid var(--color-border-subtle)',
          backgroundColor: 'var(--color-bg-surface)',
          padding: 'var(--space-5)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 'var(--space-4)',
        }}
      >
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            ACTIVE GATEWAY CACHE MODE
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: '4px' }}>
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-base)',
                fontWeight: 700,
                color: currentMode === 'isolated' ? 'var(--color-primary)' : 'var(--color-warning)',
                textTransform: 'uppercase',
              }}
            >
              {currentMode ? `${currentMode} mode` : 'Loading...'}
            </span>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
              ({currentMode === 'isolated' ? 'Tenant isolation active' : 'Prefix cache shared'})
            </span>
          </div>
        </div>

        {isAuthenticated ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
              Operator Toggle:
            </span>
            <button
              type="button"
              disabled={switchingMode || currentMode === 'isolated'}
              onClick={() => handleToggleCacheMode('isolated')}
              style={{
                padding: '4px 10px',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: currentMode === 'isolated' ? 700 : 400,
                backgroundColor: currentMode === 'isolated' ? 'var(--color-primary)' : 'var(--color-bg-base)',
                color: currentMode === 'isolated' ? 'var(--color-text-inverse)' : 'var(--color-text-secondary)',
                border: '1px solid var(--color-border-subtle)',
                cursor: currentMode === 'isolated' ? 'default' : 'pointer',
              }}
            >
              Isolated
            </button>
            <button
              type="button"
              disabled={switchingMode || currentMode === 'shared'}
              onClick={() => handleToggleCacheMode('shared')}
              style={{
                padding: '4px 10px',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: currentMode === 'shared' ? 700 : 400,
                backgroundColor: currentMode === 'shared' ? 'var(--color-warning)' : 'var(--color-bg-base)',
                color: currentMode === 'shared' ? 'var(--color-bg-base)' : 'var(--color-text-secondary)',
                border: '1px solid var(--color-border-subtle)',
                cursor: currentMode === 'shared' ? 'default' : 'pointer',
              }}
            >
              Shared
            </button>
          </div>
        ) : (
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              color: 'var(--color-text-muted)',
              border: '1px solid var(--color-border-subtle)',
              padding: '4px 8px',
            }}
          >
            Operator token required to toggle runtime cache mode
          </div>
        )}
      </div>

      {/* Decision Rule Callout */}
      <div
        style={{
          border: '1px solid var(--color-primary)',
          backgroundColor: 'var(--color-primary-soft)',
          padding: 'var(--space-4)',
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--space-1)',
        }}
      >
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-xs)',
            fontWeight: 700,
            color: 'var(--color-primary)',
          }}
        >
          EMPIRICAL DECISION CRITERIA (ARCHITECTURE §11)
        </div>
        <p
          style={{
            fontFamily: 'var(--font-sans)',
            fontSize: 'var(--text-sm)',
            color: 'var(--color-text-primary)',
            margin: 0,
            lineHeight: 1.5,
          }}
        >
          {report?.verdict_rule ||
            'Isolated mode must yield p >= 0.01 (Mann-Whitney U) and AUC < 0.75 (no leak). Shared mode must yield p < 0.01 and AUC > 0.75 (leak detected).'}
        </p>
      </div>

      {/* Timing Charts Side by Side */}
      {report && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
            gap: 'var(--space-6)',
          }}
        >
          {/* Isolated Mode Chart */}
          <TimingChart
            title="Isolated Cache Mode (Enforced Defense)"
            mode="isolated"
            stats={report.modes.isolated}
            samples={report.raw_samples?.isolated}
          />

          {/* Shared Mode Chart */}
          <TimingChart
            title="Shared Cache Mode (Vulnerability Baseline)"
            mode="shared"
            stats={report.modes.shared}
            samples={report.raw_samples?.shared}
          />
        </div>
      )}

      {/* Protocol & Limitations */}
      {report && (
        <div
          style={{
            border: '1px solid var(--color-border-subtle)',
            backgroundColor: 'var(--color-bg-surface)',
            padding: 'var(--space-6)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 'var(--space-6)',
          }}
        >
          <div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--color-text-muted)',
                textTransform: 'uppercase',
                marginBottom: 'var(--space-2)',
              }}
            >
              Benchmark Environment
            </div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-text-secondary)',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}
            >
              <div>Model: {String(report.environment.model_file || 'Qwen2.5-0.5B-Instruct-GGUF')}</div>
              <div>Platform: {String(report.environment.platform || 'Linux x86_64')}</div>
              <div>Engine: llama.cpp ({String(report.environment.llamacpp_version || 'b4100')})</div>
              <div>Trials: {String(report.protocol.n_trials_per_condition || 30)} per condition</div>
            </div>
          </div>

          <div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--color-text-muted)',
                textTransform: 'uppercase',
                marginBottom: 'var(--space-2)',
              }}
            >
              Documented Limitations
            </div>
            <ul
              style={{
                margin: 0,
                paddingLeft: 'var(--space-4)',
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-text-secondary)',
                lineHeight: 1.5,
              }}
            >
              {report.limitations.map((lim, i) => (
                <li key={i}>{lim}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
