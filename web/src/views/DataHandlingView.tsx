import React from 'react';
import type { ViewType } from '../types/api';
import { CheckCircleIcon } from '../components/common/Icons';

interface DataHandlingViewProps {
  onNavigate?: (view: ViewType) => void;
}

export const DataHandlingView: React.FC<DataHandlingViewProps> = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
      {/* Header */}
      <div
        style={{
          borderBottom: '1px solid var(--color-border-subtle)',
          paddingBottom: 'var(--space-6)',
        }}
      >
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
          Confidentiality Architecture
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
          Data Handling & Cryptographic Privacy
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
          Bayora is designed to handle proprietary red team attack techniques and proprietary
          blue team defense rules. The platform guarantees strict confidentiality during evaluation
          through commit-reveal protocols and in-memory credential boundaries.
        </p>
      </div>

      {/* 3 Pillars Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: 'var(--space-6)',
        }}
      >
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
            PILLAR 01: SEALED COMMIT-REVEAL
          </div>
          <h2
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              fontWeight: 600,
              color: 'var(--color-text-primary)',
              margin: 0,
            }}
          >
            Zero Pre-Conclusion Disclosure
          </h2>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-secondary)',
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            When an evaluation begins, Red commits a SHA-256 set digest and Blue commits
            a defense bundle digest. Inbound requests are verified against these digests.
            Neither tenant, nor unauthenticated visitors, can view the opponent&apos;s inputs
            or rules while the run is active.
          </p>
        </div>

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
            PILLAR 02: IN-MEMORY CREDENTIALS
          </div>
          <h2
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              fontWeight: 600,
              color: 'var(--color-text-primary)',
              margin: 0,
            }}
          >
            Volatile Authentication State
          </h2>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-secondary)',
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            Operator authentication tokens are stored strictly in volatile JavaScript memory
            during the active session. They are never written to <code>localStorage</code>,
            <code>sessionStorage</code>, or non-HttpOnly cookies. Refreshing the browser
            instantly clears the credential from client memory.
          </p>
        </div>

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
            PILLAR 03: EPHEMERAL FILESYSTEMS
          </div>
          <h2
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-base)',
              fontWeight: 600,
              color: 'var(--color-text-primary)',
              margin: 0,
            }}
          >
            Read-Only Containers with tmpfs
          </h2>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-secondary)',
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            All custom containers mount root filesystems with <code>read_only: true</code>.
            Temporary writes are constrained to non-executable memory-backed <code>tmpfs</code> mounts
            at <code>/tmp</code>. When containers restart, volatile artifacts are discarded,
            preventing residual cross-evaluation persistence.
          </p>
        </div>
      </div>

      {/* Data Flow Specification */}
      <div
        style={{
          border: '1px solid var(--color-border-subtle)',
          backgroundColor: 'var(--color-bg-surface)',
          padding: 'var(--space-6)',
        }}
      >
        <h2
          style={{
            fontFamily: 'var(--font-sans)',
            fontSize: 'var(--text-lg)',
            fontWeight: 600,
            color: 'var(--color-text-primary)',
            margin: '0 0 var(--space-4) 0',
          }}
        >
          Redaction Policy (SI-08)
        </h2>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 'var(--space-3)',
            fontFamily: 'var(--font-sans)',
            fontSize: 'var(--text-sm)',
            color: 'var(--color-text-secondary)',
            lineHeight: 1.6,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
            <CheckCircleIcon size={16} color="var(--color-primary)" />
            <span>
              <strong>Pre-Execution:</strong> Red commits attack corpus digests. Raw prompts are
              retained in tenant container memory only.
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
            <CheckCircleIcon size={16} color="var(--color-primary)" />
            <span>
              <strong>Mid-Execution:</strong> Model requests and audit records store SHA-256 prompt
              digests. Model response slots, timings, and KV cache hints are stripped by Gateway.
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
            <CheckCircleIcon size={16} color="var(--color-primary)" />
            <span>
              <strong>Post-Conclusion:</strong> Aggregated Attack Success Rate (ASR) is published.
              Only verified operators with authenticated <code>X-Admin-Token</code> headers can
              inspect individual prompt/response transcripts.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
