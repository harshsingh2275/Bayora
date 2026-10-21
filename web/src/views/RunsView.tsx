import React, { useEffect, useState, useCallback, useMemo } from 'react';
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

const PAGE_SIZE = 15;

// ── Icons ─────────────────────────────────────────────────────────────────────

const RefreshIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M2.5 8A5.5 5.5 0 0 1 8 2.5c2.1 0 3.94 1.19 4.87 2.93" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    <path d="M13.5 8A5.5 5.5 0 0 1 8 13.5c-2.1 0-3.94-1.19-4.87-2.93" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    <path d="M11.5 2.5L13.37 5.37 10.5 4.2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    <path d="M4.5 13.5L2.63 10.63 5.5 11.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

const PlusIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <line x1="8" y1="2" x2="8" y2="14" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round"/>
    <line x1="2" y1="8" x2="14" y2="8" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round"/>
  </svg>
);

const XIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <line x1="3" y1="3" x2="13" y2="13" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round"/>
    <line x1="13" y1="3" x2="3" y2="13" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round"/>
  </svg>
);

const ArrowRight = () => (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

// ── Run state pill ────────────────────────────────────────────────────────────

function StatePill({ state }: { state: string }) {
  const map: Record<string, { status: string }> = {
    concluded:  { status: 'ok' },
    running:    { status: 'running' },
    committing: { status: 'committing' },
    created:    { status: 'created' },
    aborted:    { status: 'aborted' },
    failed:     { status: 'failed' },
  };
  return <StatusBadge status={map[state]?.status || state} label={state} />;
}

// ── Outcome pill ──────────────────────────────────────────────────────────────

function OutcomePill({ outcome }: { outcome: string }) {
  const map: Record<string, string> = {
    blocked_input: 'warn',
    blocked_output: 'warn',
    refused: 'warn',
    complied: 'fail',
    error: 'fail',
  };
  const variant = map[outcome] || 'info';
  return <StatusBadge variant={variant as 'pass' | 'fail' | 'warn' | 'info'} label={outcome.replace(/_/g, ' ')} />;
}

// ── KPI summary cards ─────────────────────────────────────────────────────────

interface RunsKpiProps { runs: RunListItem[] }

const RunsKpiStrip: React.FC<RunsKpiProps> = ({ runs }) => {
  const total = runs.length;
  const concluded = runs.filter(r => r.state === 'concluded').length;
  const active = runs.filter(r => ['running', 'committing', 'created'].includes(r.state)).length;
  const aborted = runs.filter(r => ['aborted', 'failed'].includes(r.state)).length;

  // Unified forest/stone palette — no rainbow multi-color borders
  const forestBorder = '3px solid var(--accent-primary)';

  return (
    <div className="kpi-grid" style={{ marginBottom: 'var(--space-7)' }}>
      <div className="kpi-card">
        <div className="kpi-card__label">Total Runs</div>
        <div className="kpi-card__value">{total}</div>
      </div>
      <div className="kpi-card" style={{ borderLeft: forestBorder }}>
        <div className="kpi-card__label">Concluded</div>
        <div className="kpi-card__value">{concluded}</div>
      </div>
      <div className="kpi-card" style={{ borderLeft: forestBorder }}>
        <div className="kpi-card__label">Active / Running</div>
        <div className="kpi-card__value">{active}</div>
        {active > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-primary)', animation: 'pulse-dot 2s ease-in-out infinite', display: 'inline-block' }} />
            <span className="kpi-card__sub" style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>Live</span>
          </div>
        )}
      </div>
      <div className="kpi-card" style={{ borderLeft: forestBorder }}>
        <div className="kpi-card__label">Aborted / Failed</div>
        <div className="kpi-card__value" style={{ color: aborted > 0 ? 'var(--text-secondary)' : 'var(--text-muted)' }}>{aborted}</div>
      </div>
    </div>
  );
};

// ── Create Run Modal (top-level stable component — never inside RunsView body)
// IMPORTANT: This must live at module scope, NOT inside RunsView, so React never
// unmounts it during the 2.5s background polling re-render that updates `runs`.
// Draft string state for Attack Count and Seed lets the user freely backspace
// and type multi-digit numbers; we only parseInt on submit.

interface CreateRunModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (runId: string) => void;
  adminToken: string | null;
}

const CreateRunModal: React.FC<CreateRunModalProps> = React.memo(({ isOpen, onClose, onCreated, adminToken }) => {
  const [name, setName] = useState('');
  // Store as strings so user can clear box and type freely — no cursor jump
  const [attackCountInput, setAttackCountInput] = useState('5');
  const [seedInput, setSeedInput] = useState('42');
  const [bundle, setBundle] = useState<'baseline' | 'hardened'>('baseline');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset form only when modal opens (not on every render)
  const prevOpen = React.useRef(false);
  useEffect(() => {
    if (isOpen && !prevOpen.current) {
      setName('');
      setAttackCountInput('5');
      setSeedInput('42');
      setBundle('baseline');
      setError(null);
    }
    prevOpen.current = isOpen;
  }, [isOpen]);

  const handleClose = () => {
    setError(null);
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminToken) { setError('Operator token required'); return; }
    const attackCount = parseInt(attackCountInput, 10);
    const seed = parseInt(seedInput, 10);
    if (isNaN(attackCount) || attackCount < 1 || attackCount > 100) {
      setError('Attack Count must be a number between 1 and 100');
      return;
    }
    if (isNaN(seed)) {
      setError('Seed must be a valid integer');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const req: CreateRunRequest = {
        name: name.trim() || `eval-run-${Date.now().toString().slice(-4)}`,
        attack_count: attackCount,
        seed,
        bundle,
      };
      const res = await apiClient.createRun(req, adminToken);
      onCreated(res.run_id);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create run');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} title="Create Evaluation Run" maxWidth="480px">
      <form onSubmit={handleSubmit}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div>
            <label htmlFor="cr-run-name" style={{ display: 'block', fontWeight: 600, marginBottom: 'var(--space-1)', fontSize: 'var(--text-sm)' }}>
              Run Name
            </label>
            <input
              id="cr-run-name"
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. hardened-baseline-v1"
              style={{ width: '100%' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div>
              <label htmlFor="cr-attack-count" style={{ display: 'block', fontWeight: 600, marginBottom: 'var(--space-1)', fontSize: 'var(--text-sm)' }}>
                Attack Count (1–100)
              </label>
              {/* String input so user can freely backspace and type any number */}
              <input
                id="cr-attack-count"
                type="text"
                inputMode="numeric"
                value={attackCountInput}
                onChange={e => setAttackCountInput(e.target.value.replace(/[^0-9]/g, ''))}
                style={{ width: '100%' }}
              />
            </div>
            <div>
              <label htmlFor="cr-seed" style={{ display: 'block', fontWeight: 600, marginBottom: 'var(--space-1)', fontSize: 'var(--text-sm)' }}>
                Seed
              </label>
              <input
                id="cr-seed"
                type="text"
                inputMode="numeric"
                value={seedInput}
                onChange={e => setSeedInput(e.target.value.replace(/[^0-9-]/g, ''))}
                style={{ width: '100%' }}
              />
            </div>
          </div>

          <div>
            <label htmlFor="cr-bundle" style={{ display: 'block', fontWeight: 600, marginBottom: 'var(--space-1)', fontSize: 'var(--text-sm)' }}>
              Defense Bundle
            </label>
            <select
              id="cr-bundle"
              value={bundle}
              onChange={e => setBundle(e.target.value as 'baseline' | 'hardened')}
              style={{ width: '100%' }}
            >
              <option value="baseline">baseline — few weak rules (high ASR expected)</option>
              <option value="hardened">hardened — broader rules (lower ASR expected)</option>
            </select>
          </div>

          {error && (
            <div
              style={{
                padding: 'var(--space-3)',
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

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-3)', paddingTop: 'var(--space-2)' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleClose}
              disabled={submitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={submitting}
            >
              {submitting ? 'Creating…' : 'Create Run'}
            </button>
          </div>
        </div>
      </form>
    </Modal>
  );
});

// ── Run detail panel ──────────────────────────────────────────────────────────

interface RunDetailProps {
  run: RunListItem;
  results: RunResultsResponse | null;
  onAbort: (id: string) => void;
  onInspectItem: (runId: string, idx: number) => void;
  isAuthenticated: boolean;
  inspectLoading: boolean;
  inspectError: string | null;
}

const RunDetailPanel: React.FC<RunDetailProps> = ({
  run, results, onAbort, onInspectItem, isAuthenticated, inspectLoading, inspectError,
}) => {
  const [itemPage, setItemPage] = useState(0);
  const ITEM_PAGE_SIZE = 15;

  const pagedItems = results
    ? results.attacks.slice(itemPage * ITEM_PAGE_SIZE, (itemPage + 1) * ITEM_PAGE_SIZE)
    : [];

  const totalItemPages = results ? Math.ceil(results.attacks.length / ITEM_PAGE_SIZE) : 0;

  return (
    <div
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-md)',
        boxShadow: 'var(--shadow-elevated)',
        overflow: 'hidden',
      }}
    >
      {/* Detail header */}
      <div
        style={{
          padding: 'var(--space-5) var(--space-6)',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'var(--bg-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: 'var(--space-3)',
        }}
      >
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
            Run Detail
          </div>
          <h2
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: '1.4rem',
              fontWeight: 400,
              color: 'var(--text-primary)',
              margin: 0,
            }}
          >
            {run.name || run.run_id}
          </h2>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
            {run.run_id}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <StatePill state={run.state} />
          {isAuthenticated && ['running', 'committing', 'created'].includes(run.state) && (
            <button
              type="button"
              className="btn btn-danger btn-sm"
              onClick={() => onAbort(run.run_id)}
            >
              Abort
            </button>
          )}
        </div>
      </div>

      {/* Timeline / metadata */}
      <div
        style={{
          padding: 'var(--space-5) var(--space-6)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
          gap: 'var(--space-4)',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        {[
          { label: 'Bundle', value: <span className="badge badge-blue">{run.bundle_name}</span> },
          { label: 'Attack Count', value: run.attack_count },
          { label: 'Red Committed', value: run.red_committed ? <span className="badge badge-pass">Yes</span> : <span className="badge badge-info">Pending</span> },
          { label: 'Blue Committed', value: run.blue_committed ? <span className="badge badge-pass">Yes</span> : <span className="badge badge-info">Pending</span> },
          { label: 'Created', value: <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{new Date(run.created_at).toLocaleString()}</span> },
          { label: 'Updated', value: <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{new Date(run.updated_at).toLocaleString()}</span> },
        ].map(({ label, value }) => (
          <div key={label}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
              {label}
            </div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 500 }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Commitment digests */}
      {(run.set_digest || run.bundle_digest) && (
        <div
          style={{
            padding: 'var(--space-4) var(--space-6)',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            flexWrap: 'wrap',
            gap: 'var(--space-5)',
            background: 'rgba(180,35,24,0.03)',
          }}
        >
          {run.set_digest && (
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--accent-red-team)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>
                Red Commit Digest
              </div>
              <HashDisplay hash={run.set_digest} truncateLength={16} />
            </div>
          )}
          {run.bundle_digest && (
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--accent-blue-team)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>
                Blue Bundle Digest
              </div>
              <HashDisplay hash={run.bundle_digest} truncateLength={16} />
            </div>
          )}
        </div>
      )}

      {/* Results after conclusion */}
      {results && (
        <div style={{ padding: 'var(--space-5) var(--space-6)' }}>
          {/* Summary */}
          <div style={{ marginBottom: 'var(--space-5)' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
              Outcome Summary
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(100px, 1fr))',
                gap: 'var(--space-3)',
                marginBottom: 'var(--space-4)',
              }}
            >
              {[
                { key: 'blocked_input', label: 'Blocked (in)', color: 'var(--status-warn-text)', bg: 'var(--status-warn-bg)' },
                { key: 'blocked_output', label: 'Blocked (out)', color: 'var(--status-warn-text)', bg: 'var(--status-warn-bg)' },
                { key: 'refused', label: 'Refused', color: 'var(--status-warn-text)', bg: 'var(--status-warn-bg)' },
                { key: 'complied', label: 'Complied', color: 'var(--status-fail-text)', bg: 'var(--status-fail-bg)' },
                { key: 'error', label: 'Error', color: 'var(--text-muted)', bg: 'var(--bg-subtle)' },
              ].map(({ key, label, color, bg }) => (
                <div
                  key={key}
                  style={{
                    background: bg,
                    border: `1px solid ${color}20`,
                    borderRadius: 'var(--radius-sm)',
                    padding: 'var(--space-3)',
                    textAlign: 'center',
                  }}
                >
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.4rem', fontWeight: 700, color }}>
                    {results.aggregate[key as keyof typeof results.aggregate] ?? 0}
                  </div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--status-fail-text)' }}>
                ASR: {(results.asr * 100).toFixed(1)}%
              </span>
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                (heuristic attack success rate — % of prompts that elicited compliance)
              </span>
            </div>
            <div style={{ marginTop: 'var(--space-3)' }}>
              <OutcomeBar aggregate={results.aggregate} total={results.total} />
            </div>
          </div>

          {/* Per-attack results table */}
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
              Per-Attack Results ({results.attacks.length} total)
            </div>
            <div className="table-scroll-container">
              <table>
                <thead>
                  <tr>
                    <th style={{ whiteSpace: 'nowrap' }}>#</th>
                    <th style={{ whiteSpace: 'nowrap', minWidth: 220 }}>Prompt Preview</th>
                    <th style={{ whiteSpace: 'nowrap' }}>Outcome</th>
                    <th style={{ whiteSpace: 'nowrap' }}>Latency</th>
                    {isAuthenticated && <th style={{ whiteSpace: 'nowrap' }}>Full Item</th>}
                  </tr>
                </thead>
                <tbody>
                  {pagedItems.map((atk) => (
                    <tr key={atk.idx}>
                      <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{atk.idx}</td>
                      <td style={{ minWidth: 220 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                          {atk.prompt_preview || '—'}
                        </span>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <OutcomePill outcome={atk.outcome} />
                      </td>
                      <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                        {atk.latency_ms != null ? `${atk.latency_ms}ms` : '—'}
                      </td>
                      {isAuthenticated && (
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={() => onInspectItem(run.run_id, atk.idx)}
                          >
                            Inspect
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
              {/* Pagination for attack items */}
              {totalItemPages > 1 && (
                <div className="pagination">
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    disabled={itemPage === 0}
                    onClick={() => setItemPage(p => Math.max(0, p - 1))}
                  >
                    Previous
                  </button>
                  <div className="pagination__info">
                    Page {itemPage + 1} of {totalItemPages}
                  </div>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    disabled={itemPage >= totalItemPages - 1}
                    onClick={() => setItemPage(p => Math.min(totalItemPages - 1, p + 1))}
                  >
                    Next
                  </button>
                </div>
              )}
            </div>
            {inspectError && (
              <div style={{ marginTop: 'var(--space-3)', color: 'var(--status-fail-text)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
                {inspectError}
              </div>
            )}
            {inspectLoading && (
              <div style={{ marginTop: 'var(--space-3)', color: 'var(--text-muted)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
                Loading item…
              </div>
            )}
          </div>
        </div>
      )}

      {/* Pre-conclusion notice */}
      {run.state !== 'concluded' && run.state !== 'aborted' && run.state !== 'failed' && (
        <div
          style={{
            padding: 'var(--space-5) var(--space-6)',
            borderTop: '1px solid var(--border-subtle)',
            background: 'var(--status-info-bg)',
          }}
        >
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--status-info-text)', margin: 0 }}>
            SI-08: Prompts and results are sealed until run concludes. Audit log records digests only.
          </p>
        </div>
      )}
    </div>
  );
};

// ── Main component ────────────────────────────────────────────────────────────

type FilterState = 'all' | 'concluded' | 'running' | 'aborted';

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
  const [selectedRunId, setSelectedRunId] = useState<string | null>(externalSelectedRunId || null);
  const [runResults, setRunResults] = useState<RunResultsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter + search + pagination
  const [filter, setFilter] = useState<FilterState>('all');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);

  // Create Run Modal (state lives here only to control open/closed)
  const [isCreateOpen, setIsCreateOpen] = useState(false);

  // Operator Inspect Item Modal
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
    const interval = setInterval(fetchRuns, 2500);
    return () => clearInterval(interval);
  }, [fetchRuns]);

  useEffect(() => {
    if (externalSelectedRunId !== undefined) setSelectedRunId(externalSelectedRunId);
  }, [externalSelectedRunId]);

  useEffect(() => {
    if (!selectedRunId) { setRunResults(null); return; }
    let mounted = true;

    async function loadResults() {
      try {
        const res = await apiClient.getRunResults(selectedRunId!);
        if (mounted) setRunResults(res);
      } catch {
        if (mounted) setRunResults(null);
      }
    }

    loadResults();
    const interval = setInterval(loadResults, 3000);
    return () => { mounted = false; clearInterval(interval); };
  }, [selectedRunId]);

  // Filtered + searched list
  const filteredRuns = useMemo(() => {
    let list = runs;
    if (filter === 'concluded') list = list.filter(r => r.state === 'concluded');
    else if (filter === 'running') list = list.filter(r => ['running', 'committing', 'created'].includes(r.state));
    else if (filter === 'aborted') list = list.filter(r => ['aborted', 'failed'].includes(r.state));

    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(r => r.name?.toLowerCase().includes(q) || r.run_id.toLowerCase().includes(q));
    }
    return list;
  }, [runs, filter, search]);

  const totalPages = Math.ceil(filteredRuns.length / PAGE_SIZE);
  const pagedRuns = filteredRuns.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Reset page when filter/search changes
  useEffect(() => { setPage(0); }, [filter, search]);

  const handleSelectRun = (id: string) => {
    const next = selectedRunId === id ? null : id;
    setSelectedRunId(next);
    if (onSelectRun) onSelectRun(next);
  };

  const handleRunCreated = useCallback(async (runId: string) => {
    await fetchRuns();
    setSelectedRunId(runId);
  }, [fetchRuns]);

  const handleAbortRun = async (runId: string) => {
    if (!adminToken) return;
    if (!window.confirm(`Abort evaluation run ${runId}?`)) return;
    try {
      await apiClient.abortRun(runId, adminToken);
      await fetchRuns();
    } catch (err) {
      alert(`Failed to abort: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleInspectItem = async (runId: string, idx: number) => {
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

  const selectedRun = runs.find(r => r.run_id === selectedRunId);

  return (
    <div style={{ paddingBottom: '6rem' }}>
      <div className="container" style={{ paddingTop: '2.5rem' }}>

        {/* ── Page header ─────────────────────────────────────────────────── */}
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
            <div className="section-overline">Adversarial Testing Runs</div>
            <h1
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: 'var(--text-h1)',
                fontWeight: 400,
                color: 'var(--text-primary)',
                margin: '0 0 var(--space-2) 0',
              }}
            >
              Evaluation Runs
            </h1>
            <p style={{ fontSize: 'var(--text-body)', color: 'var(--text-secondary)', maxWidth: '640px', margin: 0 }}>
              Sealed commit-reveal evaluation runs. Commitments and final ASR scores are public; raw prompts remain sealed until conclusion (SI-08).
            </p>
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={fetchRuns}
              aria-label="Refresh runs"
            >
              <RefreshIcon /> Refresh
            </button>
            {isAuthenticated ? (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setIsCreateOpen(true)}
              >
                <PlusIcon /> Create Evaluation Run
              </button>
            ) : (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', padding: '0 var(--space-3)', height: 36, display: 'flex', alignItems: 'center', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
                Operator token required
              </span>
            )}
          </div>
        </div>

        {/* ── KPI summary ─────────────────────────────────────────────────── */}
        {!loading && <RunsKpiStrip runs={runs} />}

        {/* ── Filter pills + search ────────────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 'var(--space-3)',
            alignItems: 'center',
            marginBottom: 'var(--space-4)',
          }}
        >
          <div className="filter-pills">
            {(['all', 'concluded', 'running', 'aborted'] as FilterState[]).map(f => (
              <button
                key={f}
                type="button"
                className={`filter-pill${filter === f ? ' active' : ''}`}
                onClick={() => setFilter(f)}
              >
                {f === 'all' ? `All Runs (${runs.length})` : f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
          <input
            type="search"
            className="search-input"
            placeholder="Search by name or run ID…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            aria-label="Search runs"
          />
        </div>

        {/* ── Error ───────────────────────────────────────────────────────── */}
        {error && (
          <div
            style={{
              marginBottom: 'var(--space-4)',
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

        {/* ── Runs registry table ──────────────────────────────────────────── */}
        <div className="table-scroll-container" style={{ marginBottom: 'var(--space-7)' }}>
          <table>
            <thead>
              <tr>
                <th style={{ whiteSpace: 'nowrap' }}>Run Name / ID</th>
                <th style={{ whiteSpace: 'nowrap' }}>State</th>
                <th style={{ whiteSpace: 'nowrap' }}>Bundle</th>
                <th style={{ whiteSpace: 'nowrap' }}>Red ✓</th>
                <th style={{ whiteSpace: 'nowrap' }}>Blue ✓</th>
                <th style={{ whiteSpace: 'nowrap' }}>Created</th>
                <th style={{ whiteSpace: 'nowrap' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--space-8)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                    Loading runs…
                  </td>
                </tr>
              )}
              {!loading && pagedRuns.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--space-8)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                    {filteredRuns.length === 0 && runs.length > 0 ? 'No runs match the current filter.' : 'No evaluation runs yet. Create one with an operator token.'}
                  </td>
                </tr>
              )}
              {pagedRuns.map(run => {
                const isSelected = run.run_id === selectedRunId;
                return (
                  <tr
                    key={run.run_id}
                    style={{
                      background: isSelected ? 'rgba(46,74,54,0.05)' : undefined,
                      cursor: 'pointer',
                    }}
                    onClick={() => handleSelectRun(run.run_id)}
                  >
                    <td style={{ whiteSpace: 'nowrap', minWidth: 200 }}>
                      <div style={{ fontWeight: 600, fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                        {run.name || '—'}
                      </div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>
                        {run.run_id}
                      </div>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <StatePill state={run.state} />
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <span className="badge badge-blue">{run.bundle_name}</span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: run.red_committed ? 'var(--status-pass-text)' : 'var(--text-muted)' }}>
                        {run.red_committed ? '✓' : '—'}
                      </span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: run.blue_committed ? 'var(--status-pass-text)' : 'var(--text-muted)' }}>
                        {run.blue_committed ? '✓' : '—'}
                      </span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                      {new Date(run.created_at).toLocaleDateString()}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={e => { e.stopPropagation(); handleSelectRun(run.run_id); }}
                      >
                        {isSelected ? 'Hide' : 'Inspect'} <ArrowRight />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="pagination">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page === 0}
                onClick={() => setPage(p => Math.max(0, p - 1))}
              >
                Previous
              </button>
              <div className="pagination__info">
                Page {page + 1} of {totalPages} · {filteredRuns.length} runs
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page >= totalPages - 1}
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              >
                Next
              </button>
            </div>
          )}
        </div>

        {/* ── Run detail panel ─────────────────────────────────────────────── */}
        {selectedRun && (
          <RunDetailPanel
            run={selectedRun}
            results={runResults}
            onAbort={handleAbortRun}
            onInspectItem={handleInspectItem}
            isAuthenticated={isAuthenticated}
            inspectLoading={inspectLoading}
            inspectError={inspectError}
          />
        )}

        {/* ── Operator inspect item modal ─────────────────────────────────── */}
        {inspectItem && (
          <Modal isOpen={true} onClose={() => setInspectItem(null)} title={`Attack Item #${inspectItem.idx}`} maxWidth="640px">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>Outcome</div>
                <OutcomePill outcome={inspectItem.outcome} />
                {inspectItem.rule_id && (
                  <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    Rule: {inspectItem.rule_id}
                  </span>
                )}
              </div>
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--accent-red-team)', marginBottom: 6, textTransform: 'uppercase', fontWeight: 600 }}>Red Team Prompt</div>
                <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', background: 'var(--accent-red-bg)', border: '1px solid var(--accent-red-team)20', borderRadius: 'var(--radius-sm)', padding: 'var(--space-3)', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 200 }}>
                  {inspectItem.prompt}
                </pre>
              </div>
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--accent-blue-team)', marginBottom: 6, textTransform: 'uppercase', fontWeight: 600 }}>Model Response</div>
                <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', background: 'var(--accent-blue-bg)', border: '1px solid var(--accent-blue-team)20', borderRadius: 'var(--radius-sm)', padding: 'var(--space-3)', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 200 }}>
                  {inspectItem.response_text}
                </pre>
              </div>
              {inspectItem.latency_ms != null && (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Latency: {inspectItem.latency_ms}ms
                </div>
              )}
              <button type="button" className="btn btn-secondary" onClick={() => setInspectItem(null)}>
                <XIcon /> Close
              </button>
            </div>
          </Modal>
        )}
      </div>

      {/* ── Create Run Modal (stable top-level component — never re-mounts on poll) */}
      <CreateRunModal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        onCreated={handleRunCreated}
        adminToken={adminToken}
      />
    </div>
  );
};
