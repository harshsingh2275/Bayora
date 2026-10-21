import React from 'react';
import type { ViewType } from '../types/api';
import { ShieldCheckIcon, AlertTriangleIcon } from '../components/common/Icons';

interface ThreatModelViewProps {
  onNavigate?: (view: ViewType) => void;
}

export const ThreatModelView: React.FC<ThreatModelViewProps> = () => {
  const invariants = [
    {
      id: 'SI-01',
      title: 'Zero Privileged Containers',
      desc: 'No container is privileged. No host network or host PID namespace, no /dev passthrough, no Docker socket mount ever.',
      mechanism: 'compose: privileged: false, network_mode default bridge, no docker.sock volume',
    },
    {
      id: 'SI-02',
      title: 'Least Privilege Container Runtime',
      desc: 'Every container runs as non-root (10001:10001) with cap_drop: [ALL], no-new-privileges: true, read_only: true with tmpfs.',
      mechanism: 'compose: user 10001:10001, security_opt no-new-privileges, tmpfs /tmp',
    },
    {
      id: 'SI-03',
      title: 'Strict Network Bridge Partitions',
      desc: 'red-net, blue-net, model-red-net, model-blue-net, log-net are internal bridges. Only Gateway bridges multiple networks. Tenants have zero egress.',
      mechanism: 'compose: internal: true on tenant bridges, no default gateway, no internet access',
    },
    {
      id: 'SI-04',
      title: 'Exclusive Gateway Mediation',
      desc: 'The Gateway is the only route to the Models. Only Gateway communicates with Logger. Tenants never reach Models or Logger directly.',
      mechanism: 'compose network attachments: model-red on model-red-net, model-blue on model-blue-net, logger on log-net',
    },
    {
      id: 'SI-05',
      title: 'Constant-Time Token Validation',
      desc: 'Tenant and admin tokens are stored as hashes in Gateway memory, compared via hmac.compare_digest, never logged.',
      mechanism: 'gateway: hashlib.sha256 + hmac.compare_digest, token redaction in logs',
    },
    {
      id: 'SI-06',
      title: 'Strict Request Schemas (extra="forbid")',
      desc: 'Client-supplied model parameters (id_slot, cache_prompt) are strictly rejected. Gateway synthesizes model requests.',
      mechanism: 'pydantic: ConfigDict(extra="forbid") on all inbound API schemas',
    },
    {
      id: 'SI-07',
      title: 'Fail-Closed Audit Pipeline',
      desc: 'If the audit logger is unreachable, the gateway rejects the action with 503 Service Unavailable immediately.',
      mechanism: 'gateway: atomic audit event push before action commitment',
    },
    {
      id: 'SI-08',
      title: 'Redaction Before Run Conclusion',
      desc: 'No raw prompts, responses, or bundles in audit log or public API before run concludes. Slot/timing headers stripped.',
      mechanism: 'gateway: digests-only event logging, public API filters out unsealed bodies',
    },
    {
      id: 'SI-09',
      title: 'Data-Only Defense Bundles',
      desc: 'Defense bundles are static JSON data. Never eval, exec, import, or shell out. Regex matching enforced with timeouts.',
      mechanism: 'blue/gateway: regex timeout engine, strictly declarative rules',
    },
    {
      id: 'SI-10',
      title: 'Zero Secrets in Transit or Storage',
      desc: 'Secrets never enter git, logs, images, or client error messages. Managed via file secrets or runtime environment.',
      mechanism: '.gitignore, compose secrets, structured logging secret scrubbers',
    },
    {
      id: 'SI-11',
      title: 'Public Proxy Surface Restriction',
      desc: 'Public reverse proxy exposes /api/* only. /v1/* model endpoints return 404 through web. Public views are read-only.',
      mechanism: 'caddy: explicit handle_path /api/* reverse_proxy gateway:8000',
    },
    {
      id: 'SI-12',
      title: 'Non-Negotiable Control Invariance',
      desc: 'Never weaken a security control to make a test or feature pass.',
      mechanism: 'automated architectural regression checks and break-it suite',
    },
  ];

  return (
    <div style={{ paddingBottom: '6rem' }}>
      <div className="container" style={{ paddingTop: '2.5rem' }}>
        {/* Header */}
        <div
          style={{
            borderBottom: '1px solid var(--border-subtle)',
            paddingBottom: 'var(--space-6)',
            marginBottom: 'var(--space-8)',
          }}
        >
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: 'var(--accent-primary)',
              marginBottom: 'var(--space-2)',
            }}
          >
            Architectural Rigor & Trust Boundaries
          </div>
          <h1
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 'var(--text-h1)',
              fontWeight: 400,
              lineHeight: 1.15,
              color: 'var(--text-primary)',
              margin: '0 0 var(--space-3) 0',
            }}
          >
            Formal Threat Model & Boundaries
          </h1>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-body)',
              color: 'var(--text-secondary)',
              maxWidth: '68ch',
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            Bayora executes hostile code and untrusted prompts in a shared container environment.
            This threat model defines the trusted computing base, enforced security invariants,
            explicit non-guarantees, and failure modes.
          </p>
        </div>

        {/* 2-Column Split View: Guaranteed Protections vs Residual Risks */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
            gap: '1.5rem',
            marginBottom: 'var(--space-10)',
          }}
        >
          {/* Guaranteed Protections */}
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderTop: '3px solid var(--accent-primary)',
              borderRadius: 'var(--radius-md)',
              boxShadow: 'var(--shadow-card)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-4)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 700,
                color: 'var(--status-pass-text)',
                textTransform: 'uppercase',
              }}
            >
              <ShieldCheckIcon size={16} />
              <span>Guaranteed Protections</span>
            </div>

            <ul
              style={{
                margin: 0,
                paddingLeft: 'var(--space-4)',
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-3)',
              }}
            >
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Pre-conclusion cross-tenant inspection:</strong> Red
                cannot inspect Blue defense bundles, and Blue cannot inspect Red attack prompts prior to run conclusion.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Post-commitment input tampering:</strong> SHA-256
                commitments bind the attack set and defense rules before execution; uncommitted prompts are rejected.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Direct model access & parameter tampering:</strong> Tenants
                cannot bypass the gateway or supply sampling parameters or slot IDs.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Cross-tenant prefix-cache timing leak:</strong> In isolated
                mode, distinct slot allocation prevents prompt-cache latency leakage.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Undetected history tampering:</strong> Append-only SHA-256
                hash chain with Ed25519 signatures catches modifications, reordering, and deletions.
              </li>
            </ul>
          </div>

          {/* Residual Risks & Non-Guarantees */}
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderTop: '3px solid var(--status-warn-text)',
              borderRadius: 'var(--radius-md)',
              boxShadow: 'var(--shadow-card)',
              padding: 'var(--space-6)',
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-4)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                fontWeight: 700,
                color: 'var(--status-warn-text)',
                textTransform: 'uppercase',
              }}
            >
              <AlertTriangleIcon size={16} />
              <span>Residual Risks & Non-Guarantees</span>
            </div>

            <ul
              style={{
                margin: 0,
                paddingLeft: 'var(--space-4)',
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-3)',
              }}
            >
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Kernel & runtime escape:</strong> Containers share a single
                Linux kernel; kernel zero-days or Docker daemon vulnerabilities would bypass isolation.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>TCB compromise:</strong> Host operating system, Gateway, and
                audit logger form the trusted base; compromising them breaks integrity.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Black-box behavioral inference:</strong> Attackers observe
                which requests are blocked, allowing behavioral inference of filter rules.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Hardware resource contention timing:</strong> Heavy CPU load
                can introduce general execution jitter between concurrent tenants.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Log tail truncation after latest checkpoint:</strong> Truncating
                entries after the latest signed checkpoint requires an external witness anchor to detect.
              </li>
            </ul>
          </div>
        </div>

        {/* Security Invariants Matrix */}
        <div>
          <div style={{ marginBottom: 'var(--space-4)' }}>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-xs)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: 'var(--accent-primary)',
                marginBottom: 'var(--space-1)',
              }}
            >
              Architectural Enforcement
            </div>
            <h2
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'var(--text-h2)',
                fontWeight: 600,
                color: 'var(--text-primary)',
                margin: 0,
              }}
            >
              Security Invariant Ledger (SI-01 through SI-12)
            </h2>
          </div>

          <div className="table-scroll-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: '110px', whiteSpace: 'nowrap' }}>Invariant</th>
                  <th style={{ minWidth: 260 }}>Name & Property</th>
                  <th style={{ minWidth: 280 }}>Enforcement Mechanism</th>
                </tr>
              </thead>
              <tbody>
                {invariants.map((inv) => (
                  <tr key={inv.id}>
                    <td
                      style={{
                        whiteSpace: 'nowrap',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: 'var(--accent-primary)',
                      }}
                    >
                      {inv.id}
                    </td>
                    <td style={{ minWidth: 260 }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {inv.title}
                      </div>
                      <div
                        style={{
                          color: 'var(--text-secondary)',
                          fontFamily: 'var(--font-sans)',
                          fontSize: 'var(--text-sm)',
                          marginTop: '2px',
                          lineHeight: 1.5,
                        }}
                      >
                        {inv.desc}
                      </div>
                    </td>
                    <td style={{ minWidth: 280 }}>
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 'var(--text-xs)',
                          color: 'var(--text-secondary)',
                          background: 'var(--bg-subtle)',
                          padding: '2px 6px',
                          borderRadius: 'var(--radius-sm)',
                          display: 'inline-block',
                        }}
                      >
                        {inv.mechanism}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
