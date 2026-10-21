import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from '../api/client';
import type {
  HealthResponse,
  VerifyResponse,
  BreakitReportResponse,
  TimingReportResponse,
  RunListItem,
  ViewType,
} from '../types/api';
import { ArchitectureDiagram } from '../components/diagram/ArchitectureDiagram';

// ── Inline SVG icons for commit-reveal phases ────────────────────────────────

const PadlockIcon = () => (
  <svg width="36" height="36" viewBox="0 0 36 36" fill="none" aria-hidden="true">
    <rect x="7" y="16" width="22" height="17" rx="3" fill="var(--accent-red-bg)" stroke="var(--accent-red-team)" strokeWidth="1.5" />
    <path d="M12 16v-5a6 6 0 0 1 12 0v5" stroke="var(--accent-red-team)" strokeWidth="1.5" strokeLinecap="round" />
    <circle cx="18" cy="24" r="3" fill="var(--accent-red-team)" />
    <line x1="18" y1="27" x2="18" y2="30" stroke="var(--accent-red-team)" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

const ShieldMediationIcon = () => (
  <svg width="36" height="36" viewBox="0 0 36 36" fill="none" aria-hidden="true">
    <path d="M18 4L6 9v9c0 7.18 5.14 13.88 12 15.48C24.86 31.88 30 25.18 30 18V9L18 4z" fill="var(--accent-gateway-bg)" stroke="var(--accent-gateway)" strokeWidth="1.5" strokeLinejoin="round" />
    <path d="M13 18l3.5 3.5L24 14" stroke="var(--accent-gateway)" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const VerifiedHashIcon = () => (
  <svg width="36" height="36" viewBox="0 0 36 36" fill="none" aria-hidden="true">
    <rect x="6" y="8" width="24" height="20" rx="3" fill="var(--status-pass-bg)" stroke="var(--status-pass-text)" strokeWidth="1.5" />
    <line x1="11" y1="14" x2="25" y2="14" stroke="var(--status-pass-text)" strokeWidth="1.25" strokeLinecap="round" />
    <line x1="11" y1="18" x2="20" y2="18" stroke="var(--status-pass-text)" strokeWidth="1.25" strokeLinecap="round" />
    <circle cx="26" cy="26" r="6" fill="var(--status-pass-bg)" stroke="var(--status-pass-text)" strokeWidth="1.5" />
    <path d="M23 26l2 2 4-4" stroke="var(--status-pass-text)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const ArrowRight = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

// ── "10 Seconds" summary strip ───────────────────────────────────────────────

const TenSecondStrip: React.FC = () => (
  <div
    style={{
      display: 'flex',
      flexWrap: 'wrap',
      gap: 'var(--space-2)',
      marginBottom: 'var(--space-5)',
    }}
  >
    {[
      { num: '1', label: 'Red Team Attacks', color: 'var(--accent-red-team)', bg: 'var(--accent-red-bg)' },
      { num: '2', label: 'Gateway Mediates & Isolates', color: 'var(--accent-gateway)', bg: 'var(--accent-gateway-bg)' },
      { num: '3', label: 'SHA-256 Ledger Verifies', color: 'var(--status-pass-text)', bg: 'var(--status-pass-bg)' },
    ].map(({ num, label, color, bg }) => (
      <span
        key={num}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          padding: '6px 12px',
          borderRadius: 'var(--radius-pill)',
          background: bg,
          border: `1px solid ${color}`,
          fontSize: 'var(--text-xs)',
          fontWeight: 600,
          color,
          whiteSpace: 'nowrap',
        }}
      >
        <span
          style={{
            width: 18,
            height: 18,
            borderRadius: '50%',
            background: color,
            color: '#fff',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.65rem',
            fontWeight: 700,
            flexShrink: 0,
          }}
        >
          {num}
        </span>
        {label}
      </span>
    ))}
  </div>
);

// ── KPI Card ─────────────────────────────────────────────────────────────────

interface KpiProps {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  accentColor?: string;
}

const KpiCard: React.FC<KpiProps> = ({ label, value, sub, accentColor }) => (
  <div
    className="kpi-card"
    style={{
      borderLeft: accentColor ? `3px solid ${accentColor}` : undefined,
    }}
  >
    <div className="kpi-card__label">{label}</div>
    <div className="kpi-card__value">{value}</div>
    {sub && <div className="kpi-card__sub">{sub}</div>}
  </div>
);

// ── Commit-Reveal Pipeline Step ───────────────────────────────────────────────

interface PipelineStepProps {
  icon: React.ReactNode;
  phase: string;
  title: string;
  description: string;
  accentColor: string;
}

const PipelineStep: React.FC<PipelineStepProps> = ({ icon, phase, title, description, accentColor }) => (
  <div
    className="pipeline-step"
    style={{ borderTop: `3px solid ${accentColor}` }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
      {icon}
      <span
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-xs)',
          fontWeight: 700,
          color: accentColor,
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        }}
      >
        {phase}
      </span>
    </div>
    <div style={{ fontWeight: 600, fontSize: 'var(--text-h3)', color: 'var(--text-primary)' }}>{title}</div>
    <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
      {description}
    </p>
  </div>
);

// ── Feature card ─────────────────────────────────────────────────────────────

interface FeatureCardProps {
  overline: string;
  title: string;
  description: string;
  linkLabel: string;
  onLink: () => void;
  color: string;
  indicator?: React.ReactNode;
}

const FeatureCard: React.FC<FeatureCardProps> = ({ overline, title, description, linkLabel, onLink, color, indicator }) => (
  <div
    className="card"
    style={{
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-4)',
      justifyContent: 'space-between',
    }}
  >
    <div>
      {indicator && <div style={{ marginBottom: 'var(--space-3)' }}>{indicator}</div>}
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-xs)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          color,
          marginBottom: 'var(--space-2)',
          fontWeight: 600,
        }}
      >
        {overline}
      </div>
      <h3
        style={{
          fontSize: 'var(--text-h3)',
          fontWeight: 600,
          color: 'var(--text-primary)',
          margin: '0 0 var(--space-2) 0',
        }}
      >
        {title}
      </h3>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
        {description}
      </p>
    </div>
    <button
      type="button"
      onClick={onLink}
      style={{
        alignSelf: 'flex-start',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        border: 'none',
        background: 'none',
        padding: 0,
        fontFamily: 'var(--font-mono)',
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        color,
        cursor: 'pointer',
      }}
    >
      {linkLabel} <ArrowRight />
    </button>
  </div>
);

// ── Main view ─────────────────────────────────────────────────────────────────

interface OverviewViewProps {
  onNavigate: (view: ViewType) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [verification, setVerification] = useState<VerifyResponse | null>(null);
  const [breakit, setBreakit] = useState<BreakitReportResponse | null>(null);
  const [timing, setTiming] = useState<TimingReportResponse | null>(null);
  const [latestRun, setLatestRun] = useState<RunListItem | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [h, v, b, t, r] = await Promise.allSettled([
        apiClient.getHealth(),
        apiClient.verifyAuditLog(),
        apiClient.getBreakitReport(),
        apiClient.getTimingReport(),
        apiClient.listRuns(),
      ]);
      if (h.status === 'fulfilled') setHealth(h.value);
      if (v.status === 'fulfilled') setVerification(v.value);
      if (b.status === 'fulfilled') setBreakit(b.value);
      if (t.status === 'fulfilled') setTiming(t.value);
      if (r.status === 'fulfilled') {
        const runs = r.value.runs || [];
        setLatestRun(runs[0] ?? null);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Derived KPI values
  const healthOk = health?.status === 'ok';
  const auditOk = verification?.ok ?? null;
  const headHash = verification?.head?.hash;
  const probesPassed = breakit?.summary?.passed ?? null;
  const probesTotal = breakit?.summary?.total ?? null;
  const isolatedVerdict = timing?.modes?.isolated?.verdict;

  return (
    <div style={{ paddingBottom: '6rem' }}>

      {/* ─── HERO SECTION ─────────────────────────────────────────────────── */}
      <section style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4rem' }}>
        <div className="container" style={{ paddingTop: '3rem' }}>
          <div className="hero-grid">

            {/* Left column */}
            <div>
              {/* Category badge */}
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  marginBottom: 'var(--space-4)',
                  padding: '4px 12px',
                  borderRadius: 'var(--radius-pill)',
                  border: '1px solid var(--accent-primary)',
                  background: 'rgba(46,74,54,0.06)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  fontWeight: 600,
                  color: 'var(--accent-primary)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                }}
              >
                <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <path d="M8 2L14 5v6l-6 3L2 11V5L8 2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                </svg>
                Adversarial AI Safety Platform
              </div>

              {/* Headline */}
              <h1
                style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: 'var(--text-h1)',
                  fontWeight: 400,
                  lineHeight: 1.08,
                  letterSpacing: '-0.02em',
                  color: 'var(--text-primary)',
                  margin: '0 0 var(--space-5) 0',
                }}
              >
                A rigorous, verifiable crucible for AI red teaming.
              </h1>

              {/* 10-second strip */}
              <TenSecondStrip />

              {/* Subtext */}
              <p
                style={{
                  fontSize: 'var(--text-body)',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.65,
                  maxWidth: '56ch',
                  marginBottom: 'var(--space-7)',
                }}
              >
                Bayora runs Red Team attacker, Blue Team defender, and a client LLM
                concurrently in strict Docker network isolation. A SHA-256 hash-chain
                audit log and Ed25519 signed checkpoints guarantee non-repudiation.
              </p>

              {/* CTA buttons */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-3)', marginBottom: 'var(--space-9)' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => onNavigate('runs')}
                >
                  View Evaluation Runs <ArrowRight />
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate('audit')}
                >
                  Verify Audit Log
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => onNavigate('breakit')}
                >
                  Isolation Probes
                </button>
              </div>

              {/* KPI metrics grid */}
              <div className="kpi-grid">
                <KpiCard
                  label="Services Status"
                  value={loading ? '…' : healthOk ? 'Healthy' : 'Degraded'}
                  sub={healthOk ? 'All subsystems operational' : 'Check logs'}
                  accentColor={healthOk ? 'var(--status-pass-text)' : 'var(--status-fail-text)'}
                />
                <KpiCard
                  label="Audit Chain Head"
                  value={loading ? '…' : verification?.entries ?? '—'}
                  sub={headHash ? `#${headHash.slice(0, 8)}…` : 'Pending'}
                  accentColor="var(--accent-primary)"
                />
                <KpiCard
                  label="Isolation Probes"
                  value={loading ? '…' : probesPassed !== null ? `${probesPassed}/${probesTotal}` : '—'}
                  sub={probesPassed === probesTotal && probesTotal !== null ? 'All passed' : 'Some failed'}
                  accentColor={probesPassed === probesTotal && probesTotal !== null ? 'var(--status-pass-text)' : 'var(--status-warn-text)'}
                />
                <KpiCard
                  label="Timing Side-Channel"
                  value={loading ? '…' : isolatedVerdict === 'no_leak_detected' ? 'Defended' : isolatedVerdict === 'leak_detected' ? 'Leak' : '—'}
                  sub={isolatedVerdict === 'no_leak_detected' ? 'p ≥ 0.01 (isolated)' : 'See timing view'}
                  accentColor={isolatedVerdict === 'no_leak_detected' ? 'var(--status-pass-text)' : 'var(--status-warn-text)'}
                />
              </div>
            </div>

            {/* Right column: Architecture diagram */}
            <div>
              <div style={{ marginBottom: 'var(--space-3)' }}>
                <div className="section-overline">Container Topology & Request Flow</div>
                <h2
                  style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: '1.5rem',
                    fontWeight: 400,
                    color: 'var(--text-primary)',
                    margin: '0 0 var(--space-2) 0',
                  }}
                >
                  Enforced Security Boundaries
                </h2>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', margin: 0 }}>
                  Tenants reside on isolated internal bridges. Every interaction passes through the hardened Gateway.
                </p>
              </div>
              <ArchitectureDiagram />
            </div>
          </div>
        </div>
      </section>

      {/* ─── LATEST RUN BANNER ─────────────────────────────────────────────── */}
      {latestRun && (
        <section style={{ background: 'var(--bg-subtle)', borderBottom: '1px solid var(--border-subtle)', padding: '1.25rem 0' }}>
          <div className="container">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 'var(--space-4)',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Latest Run
                </span>
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-primary)',
                    fontWeight: 600,
                  }}
                >
                  {latestRun.name || latestRun.run_id.slice(0, 8)}
                </span>
                <RunStatePill state={latestRun.state} />
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigate('runs')}
              >
                All runs <ArrowRight />
              </button>
            </div>
          </div>
        </section>
      )}

      {/* ─── SEALED COMMIT-REVEAL PROTOCOL ────────────────────────────────── */}
      <section className="section-sep">
        <div className="container">
          <div style={{ maxWidth: '720px', marginBottom: 'var(--space-8)' }}>
            <div className="section-overline">Adversarial Protocol Integrity</div>
            <h2
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: 'var(--text-h1)',
                fontWeight: 400,
                color: 'var(--text-primary)',
                margin: '0 0 var(--space-3) 0',
              }}
            >
              Sealed Commit-Reveal Protocol
            </h2>
            <p style={{ fontSize: 'var(--text-body)', color: 'var(--text-secondary)', lineHeight: 1.65, margin: 0 }}>
              Neither party can adapt mid-run or modify their strategy after seeing the opponent's moves.
              Cryptographic hashes bind the attack corpus and defense bundle before evaluation starts.
            </p>
          </div>

          <div className="pipeline-steps">
            <PipelineStep
              icon={<PadlockIcon />}
              phase="Phase 01"
              title="Sealed Commit"
              description="Red commits SHA-256 digests of all test prompts. Blue commits the defense rule bundle digest. Both digests are immutably logged before execution begins."
              accentColor="var(--accent-red-team)"
            />
            {/* Desktop arrow connector (hidden on mobile) */}
            <PipelineStep
              icon={<ShieldMediationIcon />}
              phase="Phase 02"
              title="Mediated Execution"
              description="Prompts execute in random order through the Gateway. Audit events record digests only (SI-08). Raw prompt and response texts remain sealed to prevent mid-run leakage."
              accentColor="var(--accent-gateway)"
            />
            <PipelineStep
              icon={<VerifiedHashIcon />}
              phase="Phase 03"
              title="Verified Revelation"
              description="Upon conclusion, the ASR is computed. The independent Verifier walks the entire SHA-256 chain and checks Ed25519 signatures, proving historical non-tampering."
              accentColor="var(--status-pass-text)"
            />
          </div>
        </div>
      </section>

      {/* ─── FEATURE DEEP-DIVE CARDS ──────────────────────────────────────── */}
      <section style={{ paddingTop: '4rem', paddingBottom: '4rem', background: 'var(--bg-subtle)' }}>
        <div className="container">
          <div style={{ maxWidth: '640px', marginBottom: 'var(--space-8)' }}>
            <div className="section-overline">Security Infrastructure</div>
            <h2
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: 'var(--text-h1)',
                fontWeight: 400,
                color: 'var(--text-primary)',
                margin: '0 0 var(--space-3) 0',
              }}
            >
              Three pillars of verified isolation
            </h2>
          </div>

          <div className="feature-grid">
            <FeatureCard
              overline="Proven Boundaries"
              title="Active Isolation Probes"
              description="Automated negative security tests run from inside tenant containers: cross-tenant routing, raw Docker socket access, filesystem writes, and privilege escalation — every attempt fails as designed."
              linkLabel="Inspect Isolation Probes"
              onLink={() => onNavigate('breakit')}
              color="var(--accent-primary)"
              indicator={
                breakit ? (
                  <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--status-pass-text)' }}>
                      {breakit.summary.passed}/{breakit.summary.total} passed
                    </span>
                    {breakit.summary.failed === 0 ? (
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--status-pass-text)', animation: 'pulse-dot 2s ease-in-out infinite', display: 'inline-block' }} />
                    ) : (
                      <span style={{ color: 'var(--status-fail-text)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700 }}>
                        {breakit.summary.failed} failed
                      </span>
                    )}
                  </div>
                ) : null
              }
            />
            <FeatureCard
              overline="Microarchitectural Safety"
              title="Timing Side-Channel Analysis"
              description="Empirical timing distributions measure KV-cache cross-tenant leakage. When isolated cache mode is active, prefix cache state is strictly partitioned, yielding indistinguishable latency distributions."
              linkLabel="View Latency Distributions"
              onLink={() => onNavigate('timing')}
              color="var(--accent-gateway)"
              indicator={
                timing?.modes?.isolated ? (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600, color: timing.modes.isolated.verdict === 'no_leak_detected' ? 'var(--status-pass-text)' : 'var(--status-warn-text)' }}>
                    Isolated: {timing.modes.isolated.verdict === 'no_leak_detected' ? 'No leak detected' : 'Leak detected'} (p={timing.modes.isolated.p_value?.toFixed(4)})
                  </div>
                ) : null
              }
            />
            <FeatureCard
              overline="Cryptographic Integrity"
              title="Tamper-Evident Audit Trail"
              description="Every token issuance, commitment, model call, and bundle registration is hashed and chained. Tested against simulated tampering: row modifications, deletions, and truncations break verification."
              linkLabel="Explore Audit Log"
              onLink={() => onNavigate('audit')}
              color="var(--accent-primary)"
              indicator={
                verification ? (
                  <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700, color: auditOk ? 'var(--status-pass-text)' : 'var(--status-fail-text)' }}>
                      {auditOk ? 'Chain verified' : 'Verification failed'}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                      {verification.entries} entries, {verification.checkpoints} checkpoints
                    </span>
                  </div>
                ) : null
              }
            />
          </div>
        </div>
      </section>

      {/* ─── DARK HASH-CHAIN BLOCK STRIP ──────────────────────────────────── */}
      {verification && headHash && (
        <section
          style={{
            background: 'var(--bg-inverse)',
            color: 'var(--text-on-inverse)',
            paddingTop: '3rem',
            paddingBottom: '3rem',
          }}
        >
          <div className="container">
            <div style={{ marginBottom: 'var(--space-5)' }}>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  color: 'var(--text-muted-on-inverse)',
                  marginBottom: 'var(--space-2)',
                }}
              >
                Cryptographic Audit Chain — Live Head
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
                <span
                  style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: '1.6rem',
                    fontWeight: 400,
                    color: 'var(--text-on-inverse)',
                  }}
                >
                  {verification.ok ? 'Chain Verified' : 'Verification Error'}
                </span>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    padding: '3px 10px',
                    borderRadius: 'var(--radius-sm)',
                    background: verification.ok ? 'rgba(134,239,172,0.15)' : 'rgba(252,165,165,0.15)',
                    border: `1px solid ${verification.ok ? 'var(--status-pass-border)' : 'var(--status-fail-border)'}`,
                    color: verification.ok ? 'var(--status-pass-border)' : 'var(--status-fail-border)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                  }}
                >
                  {verification.entries} entries · {verification.checkpoints} checkpoints
                </span>
              </div>
            </div>

            {/* Block strip */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 0,
                overflowX: 'auto',
                paddingBottom: 'var(--space-3)',
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
                  minWidth: 140,
                }}
              >
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted-on-inverse)', marginBottom: 2, textTransform: 'uppercase' }}>Genesis</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-on-inverse)', fontWeight: 600 }}>Seq #0</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted-on-inverse)' }}>prev: 0000…0000</div>
              </div>
              <span style={{ color: 'var(--text-muted-on-inverse)', padding: '0 var(--space-2)', fontSize: 20, flexShrink: 0 }}>→</span>
              <div
                style={{
                  flexShrink: 0,
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.65rem',
                  color: 'var(--text-muted-on-inverse)',
                  padding: '0 var(--space-2)',
                  whiteSpace: 'nowrap',
                }}
              >
                {verification.entries - 1} intermediate entries
              </div>
              <span style={{ color: 'var(--text-muted-on-inverse)', padding: '0 var(--space-2)', fontSize: 20, flexShrink: 0 }}>→</span>
              {/* Head block */}
              <div
                style={{
                  flexShrink: 0,
                  background: verification.ok ? 'rgba(134,239,172,0.1)' : 'rgba(252,165,165,0.1)',
                  border: `1px solid ${verification.ok ? 'rgba(134,239,172,0.35)' : 'rgba(252,165,165,0.35)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: 'var(--space-3) var(--space-4)',
                  minWidth: 200,
                }}
              >
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: verification.ok ? 'var(--status-pass-border)' : 'var(--status-fail-border)', marginBottom: 2, textTransform: 'uppercase', fontWeight: 600 }}>
                  HEAD — #{verification.head?.seq}
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.72rem',
                    color: 'var(--text-on-inverse)',
                    fontWeight: 600,
                    letterSpacing: '0.02em',
                  }}
                >
                  {headHash.slice(0, 24)}…
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.68rem',
                    color: 'var(--text-muted-on-inverse)',
                    marginTop: 2,
                  }}
                >
                  {verification.ok ? 'Ed25519 sig verified' : 'Verification errors'}
                </div>
              </div>
            </div>

            <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted-on-inverse)', marginTop: 'var(--space-3)' }}>
              Truncation after the last checkpoint cannot be detected by chain alone — documented limitation. External head anchoring mitigates this.
            </p>
          </div>
        </section>
      )}
    </div>
  );
};

// Helper: run state pill
function RunStatePill({ state }: { state: string }) {
  const map: Record<string, { bg: string; color: string }> = {
    concluded:   { bg: 'var(--status-pass-bg)',  color: 'var(--status-pass-text)' },
    running:     { bg: 'var(--status-info-bg)',   color: 'var(--status-info-text)' },
    committing:  { bg: 'var(--status-info-bg)',   color: 'var(--status-info-text)' },
    created:     { bg: 'var(--status-info-bg)',   color: 'var(--status-info-text)' },
    aborted:     { bg: 'var(--status-warn-bg)',   color: 'var(--status-warn-text)' },
    failed:      { bg: 'var(--status-fail-bg)',   color: 'var(--status-fail-text)' },
  };
  const { bg, color } = map[state] ?? { bg: 'var(--bg-subtle)', color: 'var(--text-muted)' };
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '2px 8px',
        borderRadius: 'var(--radius-pill)',
        background: bg,
        color,
        fontFamily: 'var(--font-mono)',
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
      }}
    >
      {state}
    </span>
  );
}
