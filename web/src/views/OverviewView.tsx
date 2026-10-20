import React, { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import type {
  HealthResponse,
  VerifyResponse,
  BreakitReportResponse,
  TimingReportResponse,
  ViewType,
} from '../types/api';
import { ArchitectureDiagram } from '../components/diagram/ArchitectureDiagram';
import { StatusBadge } from '../components/common/StatusBadge';
import { HashDisplay } from '../components/common/HashDisplay';
import { ShieldCheckIcon, CheckCircleIcon, ArrowRightIcon } from '../components/common/Icons';

interface OverviewViewProps {
  onNavigate: (view: ViewType) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [verification, setVerification] = useState<VerifyResponse | null>(null);
  const [breakit, setBreakit] = useState<BreakitReportResponse | null>(null);
  const [timing, setTiming] = useState<TimingReportResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    async function loadData() {
      try {
        setLoading(true);
        const [h, v, b, t] = await Promise.allSettled([
          apiClient.getHealth(),
          apiClient.verifyAuditLog(),
          apiClient.getBreakitReport(),
          apiClient.getTimingReport(),
        ]);

        if (!mounted) return;

        if (h.status === 'fulfilled') setHealth(h.value);
        if (v.status === 'fulfilled') setVerification(v.value);
        if (b.status === 'fulfilled') setBreakit(b.value);
        if (t.status === 'fulfilled') setTiming(t.value);
      } catch (err) {
        if (mounted) {
          setError(err instanceof Error ? err.message : 'Failed to load platform data');
        }
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadData();
    const interval = setInterval(loadData, 10000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-12)' }}>
      {error && (
        <div
          style={{
            padding: 'var(--space-3) var(--space-4)',
            backgroundColor: 'var(--color-danger-soft)',
            border: '1px solid var(--color-danger)',
            color: 'var(--color-danger)',
            fontSize: 'var(--text-xs)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {error}
        </div>
      )}
      {/* Hero Section */}
      <section
        style={{
          borderBottom: '1px solid var(--color-border-subtle)',
          paddingBottom: 'var(--space-12)',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: 'var(--space-8)',
            alignItems: 'start',
          }}
        >
          {/* Left Column: Mission & Controls */}
          <div>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: 'var(--color-primary)',
                marginBottom: 'var(--space-3)',
                padding: '2px 8px',
                backgroundColor: 'var(--color-primary-soft)',
                border: '1px solid var(--color-primary)',
              }}
            >
              <ShieldCheckIcon size={14} />
              Formal Adversarial Safety Infrastructure
            </div>

            <h1
              style={{
                fontFamily: 'var(--font-serif)',
                fontSize: 'clamp(2.5rem, 4vw, 3.75rem)',
                fontWeight: 400,
                lineHeight: 1.1,
                color: 'var(--color-text-primary)',
                margin: '0 0 var(--space-4) 0',
                letterSpacing: '-0.02em',
              }}
            >
              A rigorous, verifiable crucible for AI red teaming.
            </h1>

            <p
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-lg)',
                lineHeight: 1.6,
                color: 'var(--color-text-secondary)',
                margin: '0 0 var(--space-6) 0',
                maxWidth: '580px',
              }}
            >
              Bayora runs red team attacker, blue team defender, and client LLM
              concurrently in an isolated, multi-container environment. Strict network
              partitions, non-privileged runtimes, and a cryptographic SHA-256 audit log
              guarantee non-repudiation.
            </p>

            {/* Primary Action Buttons */}
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 'var(--space-3)',
                marginBottom: 'var(--space-8)',
              }}
            >
              <button
                type="button"
                onClick={() => onNavigate('runs')}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  backgroundColor: 'var(--color-primary)',
                  color: 'var(--color-text-inverse)',
                  border: '1px solid var(--color-primary)',
                  padding: 'var(--space-3) var(--space-6)',
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                <span>View Evaluation Runs</span>
                <ArrowRightIcon size={16} />
              </button>

              <button
                type="button"
                onClick={() => onNavigate('audit')}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  backgroundColor: 'var(--color-bg-surface)',
                  color: 'var(--color-text-primary)',
                  border: '1px solid var(--color-border-subtle)',
                  padding: 'var(--space-3) var(--space-6)',
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                <span>Verify Audit Log</span>
              </button>

              <button
                type="button"
                onClick={() => onNavigate('breakit')}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  backgroundColor: 'transparent',
                  color: 'var(--color-text-secondary)',
                  border: '1px solid var(--color-border-subtle)',
                  padding: 'var(--space-3) var(--space-4)',
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  cursor: 'pointer',
                }}
              >
                <span>Isolation Probes</span>
              </button>
            </div>
          </div>

          {/* Right Column: Live Status Ledger */}
          <div
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
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: 'var(--color-text-muted)',
                borderBottom: '1px solid var(--color-border-subtle)',
                paddingBottom: 'var(--space-2)',
                display: 'flex',
                justifyContent: 'space-between',
              }}
            >
              <span>System Verification Ledger</span>
              <span>{loading ? 'Refreshing...' : 'Live'}</span>
            </div>

            {/* Gateway Health */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>
                Gateway & TCB
              </span>
              <StatusBadge status={health?.status === 'ok' ? 'ok' : 'pending'} />
            </div>

            {/* Hash Chained Log */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>
                  Audit Trail Integrity
                </span>
                <StatusBadge status={verification?.ok ? 'verified' : 'failed'} />
              </div>
              {verification?.head && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: '2px' }}>
                  <span style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                    HEAD ({verification.entries} entries):
                  </span>
                  <HashDisplay hash={verification.head.hash} truncateLength={10} />
                </div>
              )}
            </div>

            {/* Isolation Probes */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>
                Container Isolation Probes
              </span>
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: breakit?.summary?.failed === 0 ? 'var(--color-primary)' : 'var(--color-danger)',
                  fontWeight: 600,
                }}
              >
                {breakit
                  ? `${breakit.summary.passed}/${breakit.summary.total} Verified`
                  : 'Checking...'}
              </span>
            </div>

            {/* Side-Channel Leakage */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-secondary)' }}>
                Side-Channel (Cache Leakage)
              </span>
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: timing?.modes?.isolated?.verdict === 'no_leak_detected'
                    ? 'var(--color-primary)'
                    : 'var(--color-warning)',
                  fontWeight: 600,
                }}
              >
                {timing?.modes?.isolated?.verdict === 'no_leak_detected'
                  ? 'Defended (p >= 0.01)'
                  : timing?.verdict || 'Inspecting...'}
              </span>
            </div>

            {/* Hardening Checklist */}
            <div
              style={{
                marginTop: 'var(--space-2)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--color-border-subtle)',
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 'var(--space-2)',
                fontSize: 'var(--text-xs)',
                fontFamily: 'var(--font-mono)',
                color: 'var(--color-text-muted)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <CheckCircleIcon size={12} color="var(--color-primary)" />
                <span>cap_drop: [ALL]</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <CheckCircleIcon size={12} color="var(--color-primary)" />
                <span>read_only: true</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <CheckCircleIcon size={12} color="var(--color-primary)" />
                <span>internal: true bridges</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <CheckCircleIcon size={12} color="var(--color-primary)" />
                <span>unprivileged (10001)</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Interactive Topology Section */}
      <section>
        <div style={{ marginBottom: 'var(--space-6)' }}>
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
            Container Topology & Request Flow
          </div>
          <h2
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: 'var(--text-2xl)',
              fontWeight: 400,
              color: 'var(--color-text-primary)',
              margin: '0 0 var(--space-2) 0',
            }}
          >
            Enforced Security Boundaries
          </h2>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              color: 'var(--color-text-secondary)',
              maxWidth: '720px',
              margin: 0,
            }}
          >
            Tenants reside on isolated internal bridges with zero egress to the internet,
            the audit log, or directly to each other. Every interaction passes through the
            hardened Gateway mediation barrier.
          </p>
        </div>

        <ArchitectureDiagram />
      </section>

      {/* Protocol Walkthrough: Commit-Reveal Evaluation */}
      <section
        style={{
          borderTop: '1px solid var(--color-border-subtle)',
          paddingTop: 'var(--space-12)',
        }}
      >
        <div style={{ marginBottom: 'var(--space-8)' }}>
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
            Adversarial Protocol Integrity
          </div>
          <h2
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: 'var(--text-2xl)',
              fontWeight: 400,
              color: 'var(--color-text-primary)',
              margin: '0 0 var(--space-2) 0',
            }}
          >
            Sealed Commit-Reveal Protocol
          </h2>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              color: 'var(--color-text-secondary)',
              maxWidth: '720px',
              margin: 0,
            }}
          >
            Neither party can adapt mid-run or modify their strategy after seeing the
            opponent&apos;s moves. Cryptographic hashes bind the attack corpus and defense bundle
            before evaluation starts.
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 'var(--space-6)',
          }}
        >
          {/* Phase 1 */}
          <div
            style={{
              border: '1px solid var(--color-border-subtle)',
              backgroundColor: 'var(--color-bg-surface)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-3)',
            }}
          >
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-primary)',
                fontWeight: 700,
              }}
            >
              PHASE 01: SEALED COMMIT
            </div>
            <div
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-base)',
                fontWeight: 600,
                color: 'var(--color-text-primary)',
              }}
            >
              Cryptographic Commitment
            </div>
            <p
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-sm)',
                color: 'var(--color-text-secondary)',
                lineHeight: 1.6,
                margin: 0,
              }}
            >
              Red commits SHA-256 digests of all test prompts. Blue commits defense
              rules. State moves from <code>created</code> to <code>committing</code>.
              Digests are immutably logged into the hash-chain before execution begins.
            </p>
          </div>

          {/* Phase 2 */}
          <div
            style={{
              border: '1px solid var(--color-border-subtle)',
              backgroundColor: 'var(--color-bg-surface)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-3)',
            }}
          >
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-accent)',
                fontWeight: 700,
              }}
            >
              PHASE 02: MEDIATED EXECUTION
            </div>
            <div
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-base)',
                fontWeight: 600,
                color: 'var(--color-text-primary)',
              }}
            >
              Redacted Real-Time Evaluation
            </div>
            <p
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-sm)',
                color: 'var(--color-text-secondary)',
                lineHeight: 1.6,
                margin: 0,
              }}
            >
              Prompts execute in random order. During the run, audit events record digests
              only (SI-08). Raw prompt and response texts remain strictly sealed to prevent
              leakage to unauthorized observers.
            </p>
          </div>

          {/* Phase 3 */}
          <div
            style={{
              border: '1px solid var(--color-border-subtle)',
              backgroundColor: 'var(--color-bg-surface)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-3)',
            }}
          >
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-text-primary)',
                fontWeight: 700,
              }}
            >
              PHASE 03: VERIFIED REVELATION
            </div>
            <div
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-base)',
                fontWeight: 600,
                color: 'var(--color-text-primary)',
              }}
            >
              Independent Audit & Scoring
            </div>
            <p
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-sm)',
                color: 'var(--color-text-secondary)',
                lineHeight: 1.6,
                margin: 0,
              }}
            >
              Upon run conclusion, final attack success rate (ASR) is computed. The
              independent Verifier walks the entire SHA-256 chain and checks Ed25519
              signatures, proving historical non-tampering.
            </p>
          </div>
        </div>
      </section>

      {/* Feature Highlights Grid */}
      <section
        style={{
          borderTop: '1px solid var(--color-border-subtle)',
          paddingTop: 'var(--space-12)',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: 'var(--space-6)',
          }}
        >
          {/* Card: Active Isolation Probes */}
          <div
            style={{
              border: '1px solid var(--color-border-subtle)',
              backgroundColor: 'var(--color-bg-surface)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: 'var(--space-4)',
            }}
          >
            <div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-primary)',
                  marginBottom: 'var(--space-2)',
                }}
              >
                PROVEN BOUNDARIES
              </div>
              <h3
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-lg)',
                  fontWeight: 600,
                  color: 'var(--color-text-primary)',
                  margin: '0 0 var(--space-2) 0',
                }}
              >
                Active Isolation Probes
              </h3>
              <p
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--color-text-secondary)',
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                Automated tests execute negative security probes from tenant containers:
                cross-tenant routing, raw Docker socket access, filesystem writes, and
                privileged capability escalation. Every attempt fails as designed.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('breakit')}
              style={{
                alignSelf: 'flex-start',
                background: 'none',
                border: 'none',
                padding: 0,
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 600,
                color: 'var(--color-primary)',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
              }}
            >
              <span>Inspect Isolation Probes</span>
              <ArrowRightIcon size={12} />
            </button>
          </div>

          {/* Card: Timing Side-Channel Analysis */}
          <div
            style={{
              border: '1px solid var(--color-border-subtle)',
              backgroundColor: 'var(--color-bg-surface)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: 'var(--space-4)',
            }}
          >
            <div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-accent)',
                  marginBottom: 'var(--space-2)',
                }}
              >
                MICROARCHITECTURAL SAFETY
              </div>
              <h3
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-lg)',
                  fontWeight: 600,
                  color: 'var(--color-text-primary)',
                  margin: '0 0 var(--space-2) 0',
                }}
              >
                Timing Side-Channel Analysis
              </h3>
              <p
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--color-text-secondary)',
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                Empirical timing distributions measure KV-cache cross-tenant leakage.
                When isolated cache mode is active, prefix cache state is strictly
                partitioned, yielding indistinguishable latency distributions (p &gt;= 0.01).
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('timing')}
              style={{
                alignSelf: 'flex-start',
                background: 'none',
                border: 'none',
                padding: 0,
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 600,
                color: 'var(--color-accent)',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
              }}
            >
              <span>View Latency Distributions</span>
              <ArrowRightIcon size={12} />
            </button>
          </div>

          {/* Card: Tamper Detection & Audit Trail */}
          <div
            style={{
              border: '1px solid var(--color-border-subtle)',
              backgroundColor: 'var(--color-bg-surface)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: 'var(--space-4)',
            }}
          >
            <div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--color-text-primary)',
                  marginBottom: 'var(--space-2)',
                }}
              >
                CRYPTOGRAPHIC INTEGRITY
              </div>
              <h3
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-lg)',
                  fontWeight: 600,
                  color: 'var(--color-text-primary)',
                  margin: '0 0 var(--space-2) 0',
                }}
              >
                Tamper-Evident Audit Trail
              </h3>
              <p
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--color-text-secondary)',
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                Every token issuance, commitment, model call, and bundle registration is
                hashed and signed. Tested against simulated tampering cases: row modifications,
                deletions, and truncations break verification instantly.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('audit')}
              style={{
                alignSelf: 'flex-start',
                background: 'none',
                border: 'none',
                padding: 0,
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 600,
                color: 'var(--color-text-primary)',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
              }}
            >
              <span>Audit Trail & Tamper Tests</span>
              <ArrowRightIcon size={12} />
            </button>
          </div>
        </div>
      </section>
    </div>
  );
};
