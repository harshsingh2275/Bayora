import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from '../api/client';
import type {
  AuditLogEntry,
  VerifyResponse,
  TamperResponse,
  TamperCase,
  ViewType,
} from '../types/api';

interface AuditLogViewProps {
  onNavigate?: (view: ViewType) => void;
}

// ── Actor color map ───────────────────────────────────────────────────────────

function actorColor(actor: string): { color: string; bg: string } {
  if (actor === 'red') return { color: 'var(--accent-red-team)', bg: 'var(--accent-red-bg)' };
  if (actor === 'blue') return { color: 'var(--accent-blue-team)', bg: 'var(--accent-blue-bg)' };
  if (actor === 'gateway' || actor === 'operator') return { color: 'var(--accent-gateway)', bg: 'var(--accent-gateway-bg)' };
  return { color: 'var(--text-muted)', bg: 'var(--bg-subtle)' };
}

// ── Icons ─────────────────────────────────────────────────────────────────────

const RefreshIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M2.5 8A5.5 5.5 0 0 1 8 2.5c2.1 0 3.94 1.19 4.87 2.93" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    <path d="M13.5 8A5.5 5.5 0 0 1 8 13.5c-2.1 0-3.94-1.19-4.87-2.93" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    <path d="M11.5 2.5L13.37 5.37 10.5 4.2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    <path d="M4.5 13.5L2.63 10.63 5.5 11.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

const ShieldIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M8 2L3 4.5v4.25C3 11.75 5.5 14.25 8 15c2.5-.75 5-3.25 5-6.25V4.5L8 2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
    <path d="M5.5 8.25L7.25 10 11 6.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

const CopyIcon = () => (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <rect x="6" y="6" width="8" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.25"/>
    <path d="M4 10H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v1" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round"/>
  </svg>
);

// ── Hash-chain block strip ────────────────────────────────────────────────────

interface ChainStripProps { entries: AuditLogEntry[]; verification: VerifyResponse | null }

const ChainStrip: React.FC<ChainStripProps> = ({ entries, verification }) => {
  // Show genesis, a few middle blocks, and head
  const blocks = entries.slice(-6);

  return (
    <div
      style={{
        background: 'var(--bg-inverse)',
        borderRadius: 'var(--radius-md)',
        padding: 'var(--space-5) var(--space-6)',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 'var(--space-3)',
          marginBottom: 'var(--space-4)',
        }}
      >
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted-on-inverse)', marginBottom: 4 }}>
            Cryptographic Hash-Chain Explorer
          </div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: '1.3rem', color: 'var(--text-on-inverse)', fontWeight: 400 }}>
            {verification?.entries ?? '—'} entries · {verification?.checkpoints ?? '—'} checkpoints
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          {verification && (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                padding: '4px 12px',
                borderRadius: 'var(--radius-pill)',
                background: verification.ok ? 'rgba(134,239,172,0.15)' : 'rgba(252,165,165,0.15)',
                border: `1px solid ${verification.ok ? 'var(--status-pass-border)' : 'var(--status-fail-border)'}`,
                color: verification.ok ? 'var(--status-pass-border)' : 'var(--status-fail-border)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 700,
              }}
            >
              {verification.ok ? '✓ Chain Verified' : '✕ Verification Errors'}
            </span>
          )}
        </div>
      </div>

      {/* Block strip scroll area */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 0,
          overflowX: 'auto',
          paddingBottom: 'var(--space-2)',
        }}
      >
        {/* Genesis block */}
        <div
          style={{
            flexShrink: 0,
            background: 'var(--bg-inverse-elevated)',
            border: '1px solid var(--border-inverse)',
            borderRadius: 'var(--radius-sm)',
            padding: 'var(--space-3) var(--space-4)',
            minWidth: 150,
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-muted-on-inverse)', textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>Genesis</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-on-inverse)', fontWeight: 600 }}>Seq #0</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted-on-inverse)', marginTop: 1 }}>prev: 0000…0000</div>
        </div>

        {entries.length > 6 && (
          <>
            <span style={{ color: 'var(--text-muted-on-inverse)', padding: '0 var(--space-2)', fontSize: 16, flexShrink: 0 }}>→</span>
            <div style={{ flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted-on-inverse)', padding: '0 var(--space-2)', whiteSpace: 'nowrap' }}>
              ··· {entries.length - 6} entries ···
            </div>
          </>
        )}

        {blocks.map((entry, i) => {
          const isHead = i === blocks.length - 1;
          return (
            <React.Fragment key={entry.seq}>
              <span style={{ color: 'var(--text-muted-on-inverse)', padding: '0 var(--space-2)', fontSize: 16, flexShrink: 0 }}>→</span>
              <div
                style={{
                  flexShrink: 0,
                  background: isHead
                    ? verification?.ok ? 'rgba(134,239,172,0.08)' : 'rgba(252,165,165,0.08)'
                    : 'var(--bg-inverse-elevated)',
                  border: `1px solid ${isHead
                    ? verification?.ok ? 'rgba(134,239,172,0.3)' : 'rgba(252,165,165,0.3)'
                    : 'var(--border-inverse)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: 'var(--space-3) var(--space-4)',
                  minWidth: 160,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: isHead ? 'var(--status-pass-border)' : 'var(--text-muted-on-inverse)', textTransform: 'uppercase', fontWeight: 600 }}>
                    {isHead ? 'HEAD ' : ''}#{entry.seq}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-muted-on-inverse)' }}>
                    {entry.event}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-on-inverse)', fontWeight: 600, letterSpacing: '0.02em' }}>
                  {entry.hash.slice(0, 16)}…
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-muted-on-inverse)', marginTop: 1 }}>
                  prev: {entry.prev.slice(0, 8)}…
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>

      {/* Copy HEAD hash */}
      {verification?.head?.hash && (
        <div style={{ marginTop: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted-on-inverse)' }}>HEAD hash:</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-on-inverse)', fontWeight: 600 }}>
            {verification.head.hash}
          </span>
          <button
            type="button"
            onClick={() => navigator.clipboard?.writeText(verification.head.hash)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 3,
              padding: '2px 8px',
              border: '1px solid var(--border-inverse)',
              borderRadius: 'var(--radius-sm)',
              background: 'transparent',
              color: 'var(--text-muted-on-inverse)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.65rem',
              cursor: 'pointer',
            }}
            aria-label="Copy HEAD hash"
          >
            <CopyIcon /> Copy
          </button>
        </div>
      )}
    </div>
  );
};

// ── Tamper test matrix ────────────────────────────────────────────────────────

const TamperTestMatrix: React.FC<{ tamperReport: TamperResponse }> = ({ tamperReport }) => (
  <div
    style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border-subtle)',
      borderRadius: 'var(--radius-md)',
      overflow: 'hidden',
    }}
  >
    <div style={{ padding: 'var(--space-4) var(--space-5)', borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-subtle)' }}>
      <div style={{ fontWeight: 600, fontSize: 'var(--text-h3)', color: 'var(--text-primary)', marginBottom: 4 }}>
        Tamper Detection Results
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {tamperReport.summary.passed}/{tamperReport.summary.total} checks met expectations
        {tamperReport.summary.limitations_acknowledged > 0 && ` · ${tamperReport.summary.limitations_acknowledged} known limitation(s) documented`}
      </div>
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 0 }}>
      {tamperReport.cases.map((c: TamperCase) => (
        <div
          key={c.id}
          style={{
            padding: 'var(--space-4) var(--space-5)',
            borderBottom: '1px solid var(--border-subtle)',
            borderRight: '1px solid var(--border-subtle)',
            background: c.limitation ? 'var(--status-warn-bg)' : c.passed ? 'var(--status-pass-bg)' : 'var(--status-fail-bg)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--space-2)', marginBottom: 4 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {c.id}
            </span>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                padding: '1px 6px',
                borderRadius: 'var(--radius-sm)',
                background: c.limitation ? 'var(--status-warn-bg)' : c.passed ? 'var(--status-pass-bg)' : 'var(--status-fail-bg)',
                color: c.limitation ? 'var(--status-warn-text)' : c.passed ? 'var(--status-pass-text)' : 'var(--status-fail-text)',
                border: `1px solid ${c.limitation ? 'var(--status-warn-border)' : c.passed ? 'var(--status-pass-border)' : 'var(--status-fail-border)'}`,
                fontFamily: 'var(--font-mono)',
                fontSize: '0.65rem',
                fontWeight: 700,
                whiteSpace: 'nowrap',
              }}
            >
              {c.limitation ? 'EXPECTED LIMIT' : c.passed ? '✓ PASS' : '✕ FAIL'}
            </span>
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 4 }}>{c.description}</div>
          {c.details && (
            <details className="mono-chip">
              <summary>Details</summary>
              <pre>{c.details}</pre>
            </details>
          )}
        </div>
      ))}
    </div>
  </div>
);

// ── Main view ─────────────────────────────────────────────────────────────────

export const AuditLogView: React.FC<AuditLogViewProps> = () => {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [verification, setVerification] = useState<VerifyResponse | null>(null);
  const [tamperReport, setTamperReport] = useState<TamperResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [tamperTesting, setTamperTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);
  const [logPage, setLogPage] = useState(0);
  const LOG_PAGE_SIZE = 25;

  const fetchLogAndVerify = useCallback(async () => {
    try {
      setLoading(true);
      const [logData, verifyData] = await Promise.all([
        apiClient.getAuditLog(undefined, 200),
        apiClient.verifyAuditLog(),
      ]);
      setEntries(logData.entries || []);
      setVerification(verifyData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit trail');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchLogAndVerify(); }, [fetchLogAndVerify]);

  const handleVerifyNow = async () => {
    setVerifying(true);
    try {
      const res = await apiClient.verifyAuditLog();
      setVerification(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const handleRunTamperTest = async () => {
    setTamperTesting(true);
    try {
      const res = await apiClient.runTamperTest();
      setTamperReport(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Tamper test failed');
    } finally {
      setTamperTesting(false);
    }
  };

  const totalLogPages = Math.ceil(entries.length / LOG_PAGE_SIZE);
  const pagedEntries = entries.slice(logPage * LOG_PAGE_SIZE, (logPage + 1) * LOG_PAGE_SIZE);

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
            <div className="section-overline">Cryptographic Audit Trail</div>
            <h1
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: 'var(--text-h1)',
                fontWeight: 400,
                color: 'var(--text-primary)',
                margin: '0 0 var(--space-2) 0',
              }}
            >
              Audit Log & Independent Verifier
            </h1>
            <p style={{ fontSize: 'var(--text-body)', color: 'var(--text-secondary)', maxWidth: '640px', margin: 0 }}>
              Every security event is appended to a SHA-256 hash-chained log and Ed25519-signed at checkpoints.
              The independent Verifier validates every link from genesis to HEAD.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={fetchLogAndVerify}
              disabled={loading}
            >
              <RefreshIcon /> Refresh
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleVerifyNow}
              disabled={verifying}
            >
              <ShieldIcon /> {verifying ? 'Verifying…' : 'Verify Chain Now'}
            </button>
          </div>
        </div>

        {/* ── Error ────────────────────────────────────────────────────────── */}
        {error && (
          <div style={{ marginBottom: 'var(--space-5)', padding: 'var(--space-3) var(--space-4)', background: 'var(--status-fail-bg)', border: '1px solid var(--status-fail-border)', borderRadius: 'var(--radius-sm)', color: 'var(--status-fail-text)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
            {error}
          </div>
        )}

        {/* ── Hash-chain block explorer strip ──────────────────────────────── */}
        {(entries.length > 0 || verification) && (
          <div style={{ marginBottom: 'var(--space-8)' }}>
            <ChainStrip entries={entries} verification={verification} />
          </div>
        )}

        {/* ── Tamper Detection ──────────────────────────────────────────────── */}
        <div style={{ marginBottom: 'var(--space-8)' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 'var(--space-3)',
              marginBottom: 'var(--space-4)',
            }}
          >
            <div>
              <div className="section-overline" style={{ marginBottom: 'var(--space-1)' }}>Tamper Detection Capability</div>
              <h2
                style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: '1.5rem',
                  fontWeight: 400,
                  color: 'var(--text-primary)',
                  margin: 0,
                }}
              >
                In-Memory Tamper Demo
              </h2>
            </div>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleRunTamperTest}
              disabled={tamperTesting}
            >
              {tamperTesting ? 'Running tests…' : 'Test Tamper Detection'}
            </button>
          </div>

          {tamperReport ? (
            <TamperTestMatrix tamperReport={tamperReport} />
          ) : (
            <div
              style={{
                padding: 'var(--space-7)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                textAlign: 'center',
              }}
            >
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
                Click "Test Tamper Detection" to run the 6-attack in-memory demo against a copy of the live log.
              </p>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-2)' }}>
                Attacks: modify entry · delete entry · reorder entries · forge checkpoint · truncate before checkpoint · truncate after checkpoint
              </p>
            </div>
          )}
        </div>

        {/* ── Audit log table ───────────────────────────────────────────────── */}
        <div>
          <div style={{ marginBottom: 'var(--space-4)' }}>
            <h2
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: '1.5rem',
                fontWeight: 400,
                color: 'var(--text-primary)',
                margin: '0 0 var(--space-1) 0',
              }}
            >
              Log Entries
            </h2>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
              {entries.length} entries · raw prompts and responses never appear (SI-08) · click a row to inspect payload
            </p>
          </div>

          <div className="table-scroll-container">
            <table>
              <thead>
                <tr>
                  <th style={{ whiteSpace: 'nowrap' }}>Seq</th>
                  <th style={{ whiteSpace: 'nowrap' }}>Time</th>
                  <th style={{ whiteSpace: 'nowrap' }}>Actor</th>
                  <th style={{ whiteSpace: 'nowrap' }}>Event</th>
                  <th style={{ whiteSpace: 'nowrap' }}>Hash (short)</th>
                  <th style={{ whiteSpace: 'nowrap' }}>Prev (short)</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--space-8)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                      Loading audit log…
                    </td>
                  </tr>
                )}
                {!loading && entries.length === 0 && (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--space-8)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                      No audit entries yet.
                    </td>
                  </tr>
                )}
                {pagedEntries.map(entry => {
                  const ac = actorColor(entry.actor);
                  const isSelected = selectedEntry?.seq === entry.seq;
                  return (
                    <React.Fragment key={entry.seq}>
                      <tr
                        onClick={() => setSelectedEntry(isSelected ? null : entry)}
                        style={{ cursor: 'pointer', background: isSelected ? 'rgba(46,74,54,0.05)' : undefined }}
                      >
                        <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600 }}>
                          #{entry.seq}
                        </td>
                        <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          {new Date(entry.ts).toLocaleString()}
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              padding: '2px 7px',
                              borderRadius: 'var(--radius-sm)',
                              background: ac.bg,
                              color: ac.color,
                              border: `1px solid ${ac.color}30`,
                              fontFamily: 'var(--font-mono)',
                              fontSize: 'var(--text-xs)',
                              fontWeight: 600,
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {entry.actor}
                          </span>
                        </td>
                        <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                          {entry.event}
                        </td>
                        <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--accent-primary)' }}>
                          {entry.hash.slice(0, 12)}…
                        </td>
                        <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          {entry.prev.slice(0, 12)}…
                        </td>
                      </tr>
                      {/* Inline payload */}
                      {isSelected && (
                        <tr>
                          <td colSpan={6} style={{ padding: 0 }}>
                            <div
                              style={{
                                padding: 'var(--space-4) var(--space-5)',
                                background: 'var(--bg-subtle)',
                                borderTop: '1px solid var(--border-subtle)',
                                borderBottom: '1px solid var(--border-subtle)',
                              }}
                            >
                              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--space-2)', textTransform: 'uppercase' }}>
                                Entry Data (digests only — SI-08)
                              </div>
                              <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', overflow: 'auto', maxHeight: 200, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                                {JSON.stringify(entry.data, null, 2)}
                              </pre>
                              <div style={{ marginTop: 'var(--space-3)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                                Full hash: <span style={{ color: 'var(--accent-primary)', userSelect: 'all' }}>{entry.hash}</span>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>

            {/* Pagination */}
            {totalLogPages > 1 && (
              <div className="pagination">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={logPage === 0}
                  onClick={() => setLogPage(p => Math.max(0, p - 1))}
                >
                  Previous
                </button>
                <div className="pagination__info">
                  Page {logPage + 1} of {totalLogPages} · {entries.length} total entries
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={logPage >= totalLogPages - 1}
                  onClick={() => setLogPage(p => Math.min(totalLogPages - 1, p + 1))}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
