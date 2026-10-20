import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from '../api/client';
import type {
  RunListItem,
  RunResultsResponse,
  CreateRunRequest,
  OperatorRunItemResponse,
  ViewType,
} from '../types/api';
import { useAuth } from '../context/AuthContext';
import { StatusBadge } from '../components/common/StatusBadge';
import { HashDisplay } from '../components/common/HashDisplay';
import { OutcomeBar } from '../components/charts/OutcomeBar';
import { Modal } from '../components/common/Modal';
import {
  RefreshCwIcon,
  PlusIcon,
  XIcon,
} from '../components/common/Icons';

interface RunsViewProps {
  onNavigate?: (view: ViewType) => void;
  selectedRunId?: string | null;
  onSelectRun?: (runId: string | null) => void;
}

export const RunsView: React.FC<RunsViewProps> = ({
  selectedRunId: externalSelectedRunId,
  onSelectRun,
}) => {
  const { adminToken, isAuthenticated } = useAuth();
  const [runs, setRuns] = useState<RunListItem[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(
    externalSelectedRunId || null
  );
  const [runResults, setRunResults] = useState<RunResultsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [, setResultsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Create Run Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createAttackCount, setCreateAttackCount] = useState(5);
  const [createSeed, setCreateSeed] = useState(42);
  const [createBundle, setCreateBundle] = useState<'baseline' | 'hardened'>('baseline');
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Operator Inspect Item Modal State
  const [inspectItem, setInspectItem] = useState<OperatorRunItemResponse | null>(null);
  const [inspectLoading, setInspectLoading] = useState(false);
  const [inspectError, setInspectError] = useState<string | null>(null);

  const fetchRuns = useCallback(async () => {
    try {
      const data = await apiClient.listRuns();
      setRuns(data.runs || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch runs');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRuns();
    // Poll every 2.5s if any run is running or committing
    const interval = setInterval(() => {
      fetchRuns();
    }, 2500);
    return () => clearInterval(interval);
  }, [fetchRuns]);

  useEffect(() => {
    if (externalSelectedRunId !== undefined) {
      setSelectedRunId(externalSelectedRunId);
    }
  }, [externalSelectedRunId]);

  // When selected run changes, fetch its results
  useEffect(() => {
    if (!selectedRunId) {
      setRunResults(null);
      return;
    }

    let mounted = true;
    async function loadResults() {
      try {
        setResultsLoading(true);
        const res = await apiClient.getRunResults(selectedRunId!);
        if (mounted) {
          setRunResults(res);
        }
      } catch (err) {
        if (mounted) {
          // May not be concluded yet or error
          setRunResults(null);
        }
      } finally {
        if (mounted) setResultsLoading(false);
      }
    }

    loadResults();
    const interval = setInterval(loadResults, 3000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [selectedRunId]);

  const handleSelectRun = (id: string) => {
    const next = selectedRunId === id ? null : id;
    setSelectedRunId(next);
    if (onSelectRun) onSelectRun(next);
  };

  const handleCreateRun = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminToken) {
      setCreateError('Operator token required');
      return;
    }
    setCreateSubmitting(true);
    setCreateError(null);
    try {
      const req: CreateRunRequest = {
        name: createName || `evaluation-run-${Date.now().toString().slice(-4)}`,
        attack_count: createAttackCount,
        seed: createSeed,
        bundle: createBundle,
      };
      const res = await apiClient.createRun(req, adminToken);
      setIsCreateOpen(false);
      setCreateName('');
      await fetchRuns();
      setSelectedRunId(res.run_id);
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to initiate run');
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleAbortRun = async (runId: string) => {
    if (!adminToken) return;
    if (!window.confirm(`Abort evaluation run ${runId}?`)) return;
    try {
      await apiClient.abortRun(runId, adminToken);
      await fetchRuns();
    } catch (err) {
      alert(`Failed to abort run: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleInspectOperatorItem = async (runId: string, idx: number) => {
    if (!adminToken) return;
    setInspectLoading(true);
    setInspectError(null);
    try {
      const item = await apiClient.getOperatorRunItem(runId, idx, adminToken);
      setInspectItem(item);
    } catch (err) {
      setInspectError(err instanceof Error ? err.message : 'Failed to load item');
    } finally {
      setInspectLoading(false);
    }
  };

  const selectedRun = runs.find((r) => r.run_id === selectedRunId);

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
            Adversarial Testing Runs
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
            Evaluation Runs
          </h1>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              color: 'var(--color-text-secondary)',
              maxWidth: '680px',
              margin: 0,
            }}
          >
            Sealed commit-reveal evaluation runs between Red team attack sets and Blue team defense
            bundles. Public visitors observe cryptographic commitments and final scores; raw
            prompts remain sealed until conclusion.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <button
            type="button"
            onClick={fetchRuns}
            aria-label="Refresh runs"
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

          {isAuthenticated ? (
            <button
              type="button"
              onClick={() => setIsCreateOpen(true)}
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
              <PlusIcon size={14} />
              <span>Create Evaluation Run</span>
            </button>
          ) : (
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-text-muted)',
                padding: 'var(--space-2) var(--space-3)',
                border: '1px solid var(--color-border-subtle)',
              }}
            >
              Operator token required to create runs
            </div>
          )}
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

      {/* Main Grid: Runs Table & Detail Panel */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: selectedRun ? '1fr 1fr' : '1fr',
          gap: 'var(--space-6)',
          alignItems: 'start',
        }}
      >
        {/* Table of Runs */}
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
            <span>Evaluation Run Registry ({runs.length})</span>
            <span>Polling: 2.5s</span>
          </div>

          {loading && runs.length === 0 ? (
            <div
              style={{
                padding: 'var(--space-8)',
                textAlign: 'center',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-sm)',
                color: 'var(--color-text-muted)',
              }}
            >
              Loading runs...
            </div>
          ) : runs.length === 0 ? (
            <div
              style={{
                padding: 'var(--space-8)',
                textAlign: 'center',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-sm)',
                color: 'var(--color-text-muted)',
              }}
            >
              No evaluation runs found. Operators may initiate an evaluation run.
            </div>
          ) : (
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
                textAlign: 'left',
                fontSize: 'var(--text-xs)',
              }}
            >
              <thead>
                <tr
                  style={{
                    borderBottom: '1px solid var(--color-border-subtle)',
                    backgroundColor: 'var(--color-bg-base)',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--color-text-muted)',
                  }}
                >
                  <th style={{ padding: '8px 12px' }}>Name / ID</th>
                  <th style={{ padding: '8px 12px' }}>State</th>
                  <th style={{ padding: '8px 12px' }}>Attacks</th>
                  <th style={{ padding: '8px 12px' }}>Bundle</th>
                  <th style={{ padding: '8px 12px' }}>Commitments</th>
                  <th style={{ padding: '8px 12px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => {
                  const isSelected = r.run_id === selectedRunId;
                  const isRunning = r.state === 'running' || r.state === 'committing';
                  return (
                    <tr
                      key={r.run_id}
                      onClick={() => handleSelectRun(r.run_id)}
                      style={{
                        borderBottom: '1px solid var(--color-border-subtle)',
                        backgroundColor: isSelected
                          ? 'var(--color-bg-hover)'
                          : 'transparent',
                        cursor: 'pointer',
                      }}
                    >
                      <td style={{ padding: '10px 12px' }}>
                        <div
                          style={{
                            fontWeight: 600,
                            color: 'var(--color-text-primary)',
                            fontFamily: 'var(--font-sans)',
                          }}
                        >
                          {r.name}
                        </div>
                        <div
                          style={{
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--color-text-muted)',
                            fontSize: '11px',
                          }}
                        >
                          {r.run_id.slice(0, 8)}...
                        </div>
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <StatusBadge status={r.state} />
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)' }}>
                        {r.attack_count}
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)' }}>
                        {r.bundle_name}
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)' }}>
                        <div style={{ display: 'flex', gap: '4px' }}>
                          <span
                            title="Red Team Commitment"
                            style={{
                              color: r.red_committed ? 'var(--color-primary)' : 'var(--color-text-muted)',
                              fontWeight: r.red_committed ? 700 : 400,
                            }}
                          >
                            R:{r.red_committed ? '✓' : '-'}
                          </span>
                          <span>/</span>
                          <span
                            title="Blue Team Commitment"
                            style={{
                              color: r.blue_committed ? 'var(--color-primary)' : 'var(--color-text-muted)',
                              fontWeight: r.blue_committed ? 700 : 400,
                            }}
                          >
                            B:{r.blue_committed ? '✓' : '-'}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                        <div
                          style={{
                            display: 'inline-flex',
                            gap: 'var(--space-2)',
                            alignItems: 'center',
                          }}
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            type="button"
                            onClick={() => handleSelectRun(r.run_id)}
                            style={{
                              background: 'none',
                              border: '1px solid var(--color-border-subtle)',
                              padding: '2px 6px',
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              color: 'var(--color-text-secondary)',
                              cursor: 'pointer',
                            }}
                          >
                            {isSelected ? 'Close' : 'Inspect'}
                          </button>
                          {isAuthenticated && isRunning && (
                            <button
                              type="button"
                              onClick={() => handleAbortRun(r.run_id)}
                              title="Abort Run"
                              style={{
                                background: 'none',
                                border: '1px solid var(--color-danger)',
                                padding: '2px 6px',
                                fontFamily: 'var(--font-mono)',
                                fontSize: '11px',
                                color: 'var(--color-danger)',
                                cursor: 'pointer',
                              }}
                            >
                              Abort
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Selected Run Detail Panel */}
        {selectedRun && (
          <div
            style={{
              border: '1px solid var(--color-border-subtle)',
              backgroundColor: 'var(--color-bg-surface)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-6)',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                borderBottom: '1px solid var(--color-border-subtle)',
                paddingBottom: 'var(--space-4)',
              }}
            >
              <div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-xs)',
                    color: 'var(--color-primary)',
                    textTransform: 'uppercase',
                  }}
                >
                  Run Inspection
                </div>
                <h2
                  style={{
                    fontFamily: 'var(--font-serif)',
                    fontSize: 'var(--text-xl)',
                    margin: 'var(--space-1) 0',
                    color: 'var(--color-text-primary)',
                  }}
                >
                  {selectedRun.name}
                </h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <StatusBadge status={selectedRun.state} />
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      color: 'var(--color-text-muted)',
                    }}
                  >
                    Seed: {selectedRun.seed}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedRunId(null)}
                aria-label="Close run inspection"
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--color-text-muted)',
                }}
              >
                <XIcon size={18} />
              </button>
            </div>

            {/* Cryptographic Commitments */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                backgroundColor: 'var(--color-bg-base)',
                padding: 'var(--space-3)',
                border: '1px solid var(--color-border-subtle)',
              }}
            >
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  fontWeight: 600,
                  color: 'var(--color-text-muted)',
                  textTransform: 'uppercase',
                }}
              >
                Cryptographic Commitments (Sealed Protocol)
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <span style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', width: '90px' }}>
                  Red Corpus:
                </span>
                {selectedRun.set_digest ? (
                  <HashDisplay hash={selectedRun.set_digest} />
                ) : (
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
                    Pending commitment...
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <span style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', width: '90px' }}>
                  Blue Bundle:
                </span>
                {selectedRun.bundle_digest ? (
                  <HashDisplay hash={selectedRun.bundle_digest} />
                ) : (
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)' }}>
                    Pending commitment...
                  </span>
                )}
              </div>
            </div>

            {/* Aggregated Outcome Bar (if concluded or has results) */}
            {runResults ? (
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
                  Attack Evaluation Outcomes
                </div>
                <OutcomeBar
                  aggregate={runResults.aggregate}
                  total={runResults.total}
                  asr={runResults.asr}
                />
              </div>
            ) : selectedRun.state === 'running' || selectedRun.state === 'committing' ? (
              <div
                style={{
                  padding: 'var(--space-4)',
                  border: '1px solid var(--color-border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-text-secondary)',
                  textAlign: 'center',
                }}
              >
                Evaluation in progress... Results are sealed until conclusion to prevent leakage.
              </div>
            ) : null}

            {/* Evaluated Attacks List */}
            {runResults && runResults.attacks && runResults.attacks.length > 0 && (
              <div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    fontWeight: 600,
                    color: 'var(--color-text-muted)',
                    textTransform: 'uppercase',
                    marginBottom: 'var(--space-2)',
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}
                >
                  <span>Attack Items ({runResults.attacks.length})</span>
                  {isAuthenticated && (
                    <span style={{ color: 'var(--color-primary)' }}>
                      Operator: Click item to view raw prompt
                    </span>
                  )}
                </div>

                <div
                  style={{
                    maxHeight: '300px',
                    overflowY: 'auto',
                    border: '1px solid var(--color-border-subtle)',
                  }}
                >
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
                        }}
                      >
                        <th style={{ padding: '6px 8px', textAlign: 'left' }}>#</th>
                        <th style={{ padding: '6px 8px', textAlign: 'left' }}>Outcome</th>
                        <th style={{ padding: '6px 8px', textAlign: 'left' }}>Prompt Digest</th>
                        <th style={{ padding: '6px 8px', textAlign: 'right' }}>Latency</th>
                        {isAuthenticated && <th style={{ padding: '6px 8px', textAlign: 'right' }}>Action</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {runResults.attacks.map((att) => (
                        <tr
                          key={att.idx}
                          style={{
                            borderBottom: '1px solid var(--color-border-subtle)',
                          }}
                        >
                          <td style={{ padding: '6px 8px' }}>{att.idx}</td>
                          <td style={{ padding: '6px 8px' }}>
                            <StatusBadge status={att.outcome} />
                          </td>
                          <td style={{ padding: '6px 8px' }}>
                            <HashDisplay hash={att.prompt_digest} truncateLength={8} />
                          </td>
                          <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                            {att.latency_ms ? `${att.latency_ms.toFixed(0)} ms` : '-'}
                          </td>
                          {isAuthenticated && (
                            <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                              <button
                                type="button"
                                onClick={() => handleInspectOperatorItem(selectedRun.run_id, att.idx)}
                                style={{
                                  background: 'none',
                                  border: '1px solid var(--color-border-subtle)',
                                  padding: '2px 4px',
                                  fontSize: '10px',
                                  fontFamily: 'var(--font-mono)',
                                  cursor: 'pointer',
                                  color: 'var(--color-primary)',
                                }}
                              >
                                View Raw
                              </button>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Operator Create Run Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Create Evaluation Run (Operator Action)"
      >
        <form onSubmit={handleCreateRun} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {createError && (
            <div
              style={{
                padding: 'var(--space-3)',
                backgroundColor: 'var(--color-danger-soft)',
                border: '1px solid var(--color-danger)',
                color: 'var(--color-danger)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
              }}
            >
              {createError}
            </div>
          )}

          <div>
            <label
              htmlFor="create-name"
              style={{
                display: 'block',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-text-secondary)',
                marginBottom: '4px',
              }}
            >
              Run Name
            </label>
            <input
              id="create-name"
              type="text"
              placeholder="e.g. jailbreak-suite-alpha"
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              style={{
                width: '100%',
                padding: 'var(--space-2)',
                backgroundColor: 'var(--color-bg-base)',
                border: '1px solid var(--color-border-subtle)',
                color: 'var(--color-text-primary)',
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-sm)',
              }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div>
              <label
                htmlFor="create-attacks"
                style={{
                  display: 'block',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-text-secondary)',
                  marginBottom: '4px',
                }}
              >
                Attack Count (1-50)
              </label>
              <input
                id="create-attacks"
                type="number"
                min={1}
                max={50}
                value={createAttackCount}
                onChange={(e) => setCreateAttackCount(Number(e.target.value))}
                style={{
                  width: '100%',
                  padding: 'var(--space-2)',
                  backgroundColor: 'var(--color-bg-base)',
                  border: '1px solid var(--color-border-subtle)',
                  color: 'var(--color-text-primary)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-sm)',
                }}
              />
            </div>

            <div>
              <label
                htmlFor="create-seed"
                style={{
                  display: 'block',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-text-secondary)',
                  marginBottom: '4px',
                }}
              >
                Seed
              </label>
              <input
                id="create-seed"
                type="number"
                value={createSeed}
                onChange={(e) => setCreateSeed(Number(e.target.value))}
                style={{
                  width: '100%',
                  padding: 'var(--space-2)',
                  backgroundColor: 'var(--color-bg-base)',
                  border: '1px solid var(--color-border-subtle)',
                  color: 'var(--color-text-primary)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-sm)',
                }}
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="create-bundle"
              style={{
                display: 'block',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-text-secondary)',
                marginBottom: '4px',
              }}
            >
              Defense Bundle
            </label>
            <select
              id="create-bundle"
              value={createBundle}
              onChange={(e) => setCreateBundle(e.target.value as 'baseline' | 'hardened')}
              style={{
                width: '100%',
                padding: 'var(--space-2)',
                backgroundColor: 'var(--color-bg-base)',
                border: '1px solid var(--color-border-subtle)',
                color: 'var(--color-text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-sm)',
              }}
            >
              <option value="baseline">baseline (minimal heuristics)</option>
              <option value="hardened">hardened (strict regex + output filtering)</option>
            </select>
          </div>

          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              gap: 'var(--space-2)',
              marginTop: 'var(--space-2)',
            }}
          >
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              style={{
                padding: 'var(--space-2) var(--space-4)',
                backgroundColor: 'transparent',
                border: '1px solid var(--color-border-subtle)',
                color: 'var(--color-text-secondary)',
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-xs)',
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createSubmitting}
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
              {createSubmitting ? 'Initiating...' : 'Initiate Run'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Operator Inspect Raw Item Modal */}
      <Modal
        isOpen={!!inspectItem || inspectLoading || !!inspectError}
        onClose={() => {
          setInspectItem(null);
          setInspectError(null);
        }}
        title={`Raw Attack Item ${inspectItem ? `#${inspectItem.idx}` : ''} (Operator Access)`}
      >
        {inspectLoading && (
          <div style={{ padding: 'var(--space-4)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
            Loading attack prompt transcript...
          </div>
        )}
        {inspectError && (
          <div
            style={{
              padding: 'var(--space-3)',
              backgroundColor: 'var(--color-danger-soft)',
              border: '1px solid var(--color-danger)',
              color: 'var(--color-danger)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              marginBottom: 'var(--space-3)',
            }}
          >
            {inspectError}
          </div>
        )}
        {inspectItem && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                gap: 'var(--space-2)',
                backgroundColor: 'var(--color-bg-base)',
                padding: 'var(--space-3)',
                border: '1px solid var(--color-border-subtle)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
              }}
            >
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Outcome: </span>
                <StatusBadge status={inspectItem.outcome} />
              </div>
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Rule ID: </span>
                <span>{inspectItem.rule_id || 'None'}</span>
              </div>
              <div>
                <span style={{ color: 'var(--color-text-muted)' }}>Latency: </span>
                <span>{inspectItem.latency_ms ? `${inspectItem.latency_ms.toFixed(1)} ms` : '-'}</span>
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
                PROMPT (ATTACK CORPUS)
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
                  maxHeight: '180px',
                  overflowY: 'auto',
                }}
              >
                {inspectItem.prompt}
              </pre>
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
                RESPONSE (MODEL / DEFENSE)
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
                  maxHeight: '180px',
                  overflowY: 'auto',
                }}
              >
                {inspectItem.response_text || '(Empty or Blocked)'}
              </pre>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setInspectItem(null)}
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
