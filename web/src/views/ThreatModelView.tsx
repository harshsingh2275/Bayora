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
      desc: 'red-net, blue-net, model-net, log-net are internal bridges. Only Gateway bridges multiple networks. Tenants have zero egress.',
      mechanism: 'compose: internal: true on tenant bridges, no default gateway, no internet access',
    },
    {
      id: 'SI-04',
      title: 'Exclusive Gateway Mediation',
      desc: 'The Gateway is the only route to the Model. Only Gateway communicates with Logger. Tenants never reach Model or Logger directly.',
      mechanism: 'compose network attachments: model and logger only on internal model-net / log-net',
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
          Architectural Rigor
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
          Formal Threat Model & Boundaries
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
          Bayora executes hostile code and untrusted prompts in a shared container environment.
          This threat model defines the trusted computing base, enforced security invariants,
          explicit non-guarantees, and failure modes.
        </p>
      </div>

      {/* Protects vs Does Not Protect Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
          gap: 'var(--space-6)',
        }}
      >
        {/* Protects Against */}
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
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              fontWeight: 700,
              color: 'var(--color-primary)',
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
              color: 'var(--color-text-secondary)',
              lineHeight: 1.6,
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-3)',
            }}
          >
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Pre-conclusion cross-tenant inspection:</strong> Red
              cannot inspect Blue defense bundles, and Blue cannot inspect Red attack prompts prior to run conclusion.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Post-commitment input tampering:</strong> SHA-256
              commitments bind the attack set and defense rules before execution; uncommitted prompts are rejected.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Direct model access & parameter tampering:</strong> Tenants
              cannot bypass the gateway or supply sampling parameters or slot IDs.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Cross-tenant prefix-cache timing leak:</strong> In isolated
              mode, distinct slot allocation prevents prompt-cache latency leakage.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Undetected history tampering:</strong> Append-only SHA-256
              hash chain with Ed25519 signatures catches modifications, reordering, and deletions.
            </li>
          </ul>
        </div>

        {/* Does Not Protect Against */}
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
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              fontWeight: 700,
              color: 'var(--color-accent)',
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
              color: 'var(--color-text-secondary)',
              lineHeight: 1.6,
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-3)',
            }}
          >
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Kernel & runtime escape:</strong> Containers share a single
              Linux kernel; kernel zero-days or Docker daemon vulnerabilities would bypass isolation.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>TCB compromise:</strong> Host operating system, Gateway, and
              audit logger form the trusted base; compromising them breaks integrity.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Black-box behavioral inference:</strong> Attackers observe
              which requests are blocked, allowing behavioral inference of filter rules.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Hardware resource contention timing:</strong> Heavy CPU load
              can introduce general execution jitter between concurrent tenants.
            </li>
            <li>
              <strong style={{ color: 'var(--color-text-primary)' }}>Log tail truncation after latest checkpoint:</strong> Truncating
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
              color: 'var(--color-primary)',
              marginBottom: 'var(--space-1)',
            }}
          >
            Architectural Enforcement
          </div>
          <h2
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-xl)',
              fontWeight: 600,
              color: 'var(--color-text-primary)',
              margin: 0,
            }}
          >
            Security Invariant Ledger (SI-01 through SI-12)
          </h2>
        </div>

        <div
          style={{
            border: '1px solid var(--color-border-subtle)',
            backgroundColor: 'var(--color-bg-surface)',
            overflowX: 'auto',
          }}
        >
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              fontSize: 'var(--text-xs)',
              textAlign: 'left',
            }}
          >
            <thead>
              <tr
                style={{
                  backgroundColor: 'var(--color-bg-base)',
                  borderBottom: '1px solid var(--color-border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-text-muted)',
                }}
              >
                <th style={{ padding: '8px 12px', width: '90px' }}>Invariant</th>
                <th style={{ padding: '8px 12px' }}>Name & Property</th>
                <th style={{ padding: '8px 12px' }}>Enforcement Mechanism</th>
              </tr>
            </thead>
            <tbody>
              {invariants.map((inv) => (
                <tr
                  key={inv.id}
                  style={{
                    borderBottom: '1px solid var(--color-border-subtle)',
                  }}
                >
                  <td
                    style={{
                      padding: '10px 12px',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      color: 'var(--color-primary)',
                    }}
                  >
                    {inv.id}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      {inv.title}
                    </div>
                    <div
                      style={{
                        color: 'var(--color-text-secondary)',
                        fontFamily: 'var(--font-sans)',
                        marginTop: '2px',
                        lineHeight: 1.5,
                      }}
                    >
                      {inv.desc}
                    </div>
                  </td>
                  <td
                    style={{
                      padding: '10px 12px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-text-muted)',
                      fontSize: '11px',
                    }}
                  >
                    {inv.mechanism}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
