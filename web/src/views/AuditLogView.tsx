import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from '../api/client';
import type {
  AuditLogEntry,
  VerifyResponse,
  TamperResponse,
  ViewType,
} from '../types/api';
import { StatusBadge } from '../components/common/StatusBadge';
import { HashDisplay } from '../components/common/HashDisplay';
import { Modal } from '../components/common/Modal';
import {
  ShieldCheckIcon,
  RefreshCwIcon,
} from '../components/common/Icons';

interface AuditLogViewProps {
  onNavigate?: (view: ViewType) => void;
}

export const AuditLogView: React.FC<AuditLogViewProps> = () => {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [verification, setVerification] = useState<VerifyResponse | null>(null);
  const [tamperReport, setTamperReport] = useState<TamperResponse | null>(null);

  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [tamperTesting, setTamperTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Inspector modal for entry payload
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);

  const fetchLogAndVerify = useCallback(async () => {
    try {
      setLoading(true);
      const [logData, verifyData] = await Promise.all([
        apiClient.getAuditLog(100),
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

  useEffect(() => {
    fetchLogAndVerify();
  }, [fetchLogAndVerify]);

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
      setError(err instanceof Error ? err.message : 'Tamper test execution failed');
    } finally {
      setTamperTesting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
      {/* Header */}
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
            Cryptographic Audit Trail
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
            Audit Log & Independent Verifier
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
            Every security event (commitments, model invocations, token lifecycle) is
            appended to a SHA-256 hash-chained log signed with Ed25519. The independent
            Verifier validates every link from genesis to HEAD.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
          <button
            type="button"
            onClick={fetchLogAndVerify}
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

          <button
            type="button"
            onClick={handleVerifyNow}
            disabled={verifying}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              backgroundColor: 'var(--color-primary)',
              color: 'var(--color-text-inverse)',
              border: '1px solid var(--color-primary)',
              padding: 'var(--space-2) var(--space-4)',
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <ShieldCheckIcon size={14} />
            <span>{verifying ? 'Verifying Chain...' : 'Verify Chain Now'}</span>
          </button>
        </div>
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

      {/* Verification Head Banner */}
      <div
        style={{
          border: '1px solid var(--color-border-subtle)',
          backgroundColor: 'var(--color-bg-surface)',
          padding: 'var(--space-5)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 'var(--space-4)',
          alignItems: 'center',
        }}
      >
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            CHAIN STATUS
          </div>
          <div style={{ marginTop: '4px' }}>
            <StatusBadge status={verification?.ok ? 'verified' : 'failed'} />
          </div>
        </div>

        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            VALIDATED ENTRIES / CHECKPOINTS
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-base)',
              fontWeight: 700,
              color: 'var(--color-text-primary)',
              marginTop: '2px',
            }}
          >
            {verification?.entries ?? '-'} entries · {verification?.checkpoints ?? 0} checkpoints
          </div>
        </div>

        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            LATEST HEAD DIGEST
          </div>
          <div style={{ marginTop: '2px' }}>
            {verification?.head ? (
              <HashDisplay hash={verification.head.hash} />
            ) : (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>None</span>
            )}
          </div>
        </div>
      </div>

      {/* Tamper Detection Analysis Section */}
      <section
        style={{
          border: '1px solid var(--color-border-subtle)',
          backgroundColor: 'var(--color-bg-surface)',
          padding: 'var(--space-6)',
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--space-4)',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: 'var(--space-4)',
          }}
        >
          <div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--color-primary)',
                textTransform: 'uppercase',
                fontWeight: 600,
              }}
            >
              Integrity Assurance
            </div>
            <h2
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-lg)',
                fontWeight: 600,
                color: 'var(--color-text-primary)',
                margin: '2px 0',
              }}
            >
              Tamper Detection Capability
            </h2>
            <p
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-sm)',
                color: 'var(--color-text-secondary)',
                margin: 0,
                maxWidth: '680px',
              }}
            >
              Simulates intentional attacks against audit log integrity (modifying row data,
              deleting intermediate entries, and truncating the log). Proves the verifier
              mathematically flags all unauthorized edits.
            </p>
          </div>

          <button
            type="button"
            onClick={handleRunTamperTest}
            disabled={tamperTesting}
            style={{
              padding: 'var(--space-2) var(--space-4)',
              backgroundColor: 'var(--color-bg-base)',
              border: '1px solid var(--color-primary)',
              color: 'var(--color-primary)',
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            {tamperTesting ? 'Running Integrity Test...' : 'Test Tamper Detection'}
          </button>
        </div>

        {tamperReport && (
          <div style={{ marginTop: 'var(--space-2)' }}>
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
                fontSize: 'var(--text-xs)',
                fontFamily: 'var(--font-mono)',
              }}
            >
              <thead>
                <tr
                  style={{
                    backgroundColor: 'var(--color-bg-base)',
                    borderBottom: '1px solid var(--color-border-subtle)',
                    color: 'var(--color-text-muted)',
                    textAlign: 'left',
                  }}
                >
                  <th style={{ padding: '8px' }}>Test Case</th>
                  <th style={{ padding: '8px' }}>Description</th>
                  <th style={{ padding: '8px' }}>Tamper Detected</th>
                  <th style={{ padding: '8px' }}>Expectation</th>
                  <th style={{ padding: '8px', textAlign: 'right' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {tamperReport.cases.map((c) => (
                  <tr
                    key={c.id}
                    style={{
                      borderBottom: '1px solid var(--color-border-subtle)',
                      backgroundColor: c.limitation ? 'var(--color-bg-hover)' : 'transparent',
                    }}
                  >
                    <td style={{ padding: '8px', fontWeight: 600 }}>{c.id}</td>
                    <td style={{ padding: '8px', fontFamily: 'var(--font-sans)' }}>
                      <div>{c.description}</div>
                      {c.limitation && (
                        <div
                          style={{
                            fontSize: '11px',
                            color: 'var(--color-text-muted)',
                            marginTop: '2px',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          * Limitation note: Without external witness anchors, tail truncation
                          is indistinguishable from earlier valid history.
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '8px' }}>
                      <span
                        style={{
                          color: c.detected ? 'var(--color-danger)' : 'var(--color-primary)',
                          fontWeight: 600,
                        }}
                      >
                        {c.detected ? 'DETECTED' : 'NOT DETECTED'}
                      </span>
                    </td>
                    <td style={{ padding: '8px' }}>
                      {c.expected_detection ? 'Expects Detection' : 'Expected Baseline'}
                    </td>
                    <td style={{ padding: '8px', textAlign: 'right' }}>
                      <StatusBadge status={c.passed ? 'verified' : 'failed'} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Audit Log Entries Table */}
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
          <span>Audit Log Sequence (Most Recent {entries.length} Events)</span>
          <span>Hash Chained: SHA-256</span>
        </div>

        {loading && entries.length === 0 ? (
          <div
            style={{
              padding: 'var(--space-8)',
              textAlign: 'center',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-muted)',
            }}
          >
            Loading audit records...
          </div>
        ) : entries.length === 0 ? (
          <div
            style={{
              padding: 'var(--space-8)',
              textAlign: 'center',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-muted)',
            }}
          >
            No audit log entries recorded yet.
          </div>
        ) : (
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              fontSize: 'var(--text-xs)',
              fontFamily: 'var(--font-mono)',
              textAlign: 'left',
            }}
          >
            <thead>
              <tr
                style={{
                  backgroundColor: 'var(--color-bg-base)',
                  borderBottom: '1px solid var(--color-border-subtle)',
                  color: 'var(--color-text-muted)',
                }}
              >
                <th style={{ padding: '8px 12px' }}>Seq</th>
                <th style={{ padding: '8px 12px' }}>Timestamp</th>
                <th style={{ padding: '8px 12px' }}>Actor</th>
                <th style={{ padding: '8px 12px' }}>Event</th>
                <th style={{ padding: '8px 12px' }}>Hash</th>
                <th style={{ padding: '8px 12px' }}>Prev Hash</th>
                <th style={{ padding: '8px 12px', textAlign: 'right' }}>Payload</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr
                  key={entry.seq}
                  style={{
                    borderBottom: '1px solid var(--color-border-subtle)',
                  }}
                >
                  <td style={{ padding: '8px 12px', fontWeight: 700 }}>#{entry.seq}</td>
                  <td style={{ padding: '8px 12px', color: 'var(--color-text-muted)' }}>
                    {entry.ts ? new Date(entry.ts).toLocaleTimeString() : '-'}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span
                      style={{
                        padding: '2px 6px',
                        backgroundColor: 'var(--color-bg-hover)',
                        border: '1px solid var(--color-border-subtle)',
                      }}
                    >
                      {entry.actor}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {entry.event}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <HashDisplay hash={entry.hash} truncateLength={8} />
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <HashDisplay hash={entry.prev} truncateLength={8} />
                  </td>
                  <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                    <button
                      type="button"
                      onClick={() => setSelectedEntry(entry)}
                      style={{
                        background: 'none',
                        border: '1px solid var(--color-border-subtle)',
                        padding: '2px 6px',
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)',
                        cursor: 'pointer',
                        color: 'var(--color-primary)',
                      }}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Entry Payload Modal */}
      <Modal
        isOpen={!!selectedEntry}
        onClose={() => setSelectedEntry(null)}
        title={`Audit Entry #${selectedEntry?.seq}: ${selectedEntry?.event}`}
      >
        {selectedEntry && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 'var(--space-2)',
                backgroundColor: 'var(--color-bg-base)',
                padding: 'var(--space-3)',
                border: '1px solid var(--color-border-subtle)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
              }}
            >
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Actor: </span>
                <span>{selectedEntry.actor}</span>
              </div>
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Timestamp: </span>
                <span>{selectedEntry.ts}</span>
              </div>
              <div style={{ gridColumn: 'span 2' }}>
                <span style={{ color: 'var(--color-text-muted)' }}>Run ID: </span>
                <span>{selectedEntry.run_id || 'None (System event)'}</span>
              </div>
            </div>

            <div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-text-muted)',
                  marginBottom: '4px',
                }}
              >
                PAYLOAD DATA (SI-08: REDACTED PRE-CONCLUSION)
              </div>
              <pre
                style={{
                  margin: 0,
                  padding: 'var(--space-3)',
                  backgroundColor: 'var(--color-bg-base)',
                  border: '1px solid var(--color-border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  maxHeight: '260px',
                  overflowY: 'auto',
                }}
              >
                {JSON.stringify(selectedEntry.data, null, 2)}
              </pre>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setSelectedEntry(null)}
                style={{
                  padding: 'var(--space-2) var(--space-4)',
                  backgroundColor: 'var(--color-primary)',
                  border: '1px solid var(--color-primary)',
                  color: 'var(--color-text-inverse)',
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-xs)',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Close
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
