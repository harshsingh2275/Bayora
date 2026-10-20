import React from 'react';
import type { ViewType } from '../../types/api';

interface FooterProps {
  currentView: ViewType;
  onNavigate: (view: ViewType) => void;
}

export const Footer: React.FC<FooterProps> = ({ currentView, onNavigate }) => {
  return (
    <footer
      style={{
        borderTop: '1px solid var(--color-border-subtle)',
        backgroundColor: 'var(--color-bg-surface)',
        padding: 'var(--space-8) var(--space-6)',
        marginTop: 'auto',
      }}
    >
      <div
        style={{
          maxWidth: '1440px',
          margin: '0 auto',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: 'var(--space-8)',
        }}
      >
        {/* Brand and Mission */}
        <div>
          <div
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: 'var(--text-xl)',
              color: 'var(--color-text-primary)',
              marginBottom: 'var(--space-2)',
            }}
          >
            Bayora Security Platform
          </div>
          <p
            style={{
              fontFamily: 'var(--font-sans)',
              fontSize: 'var(--text-sm)',
              color: 'var(--color-text-secondary)',
              lineHeight: 1.6,
              maxWidth: '380px',
              margin: '0 0 var(--space-4) 0',
            }}
          >
            Secure, verifiable infrastructure for concurrent red team, blue team,
            and client LLM evaluation. Cryptographically audited, isolated, and verified.
          </p>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              fontSize: 'var(--text-xs)',
              fontFamily: 'var(--font-mono)',
              color: 'var(--color-text-muted)',
              border: '1px solid var(--color-border-subtle)',
              padding: '2px 8px',
            }}
          >
            <span>SHA-256 Chain</span>
            <span>•</span>
            <span>Ed25519 Signatures</span>
          </div>
        </div>

        {/* Platform Navigation */}
        <div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--color-text-muted)',
              marginBottom: 'var(--space-3)',
            }}
          >
            Platform Views
          </div>
          <ul
            style={{
              listStyle: 'none',
              padding: 0,
              margin: 0,
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-2)',
            }}
          >
            {[
              { id: 'overview' as ViewType, label: 'Platform Overview' },
              { id: 'runs' as ViewType, label: 'Evaluation Runs' },
              { id: 'audit' as ViewType, label: 'Audit Log & Verifier' },
              { id: 'breakit' as ViewType, label: 'Active Isolation Probes' },
              { id: 'timing' as ViewType, label: 'Timing Side-Channel' },
              { id: 'threat' as ViewType, label: 'Threat Model' },
              { id: 'data-handling' as ViewType, label: 'Data Handling' },
            ].map((item) => (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => onNavigate(item.id)}
                  style={{
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    fontFamily: 'var(--font-sans)',
                    fontSize: 'var(--text-sm)',
                    color:
                      currentView === item.id
                        ? 'var(--color-primary)'
                        : 'var(--color-text-secondary)',
                    fontWeight: currentView === item.id ? 600 : 400,
                    cursor: 'pointer',
                    textAlign: 'left',
                    textDecoration: currentView === item.id ? 'underline' : 'none',
                  }}
                >
                  {item.label}
                </button>
              </li>
            ))}
          </ul>
        </div>

        {/* Architecture Guarantees */}
        <div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--color-text-muted)',
              marginBottom: 'var(--space-3)',
            }}
          >
            Guarantees
          </div>
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-2)',
              fontSize: 'var(--text-xs)',
              fontFamily: 'var(--font-mono)',
              color: 'var(--color-text-secondary)',
            }}
          >
            <div>SI-01: Zero Privileged Containers</div>
            <div>SI-03: Internal Bridge Isolation</div>
            <div>SI-05: Constant-Time Token Digest</div>
            <div>SI-07: Fail-Closed Audit Pipeline</div>
            <div>SI-08: Prompt Redaction Pre-Conclusion</div>
          </div>
        </div>

        {/* Resources & Source */}
        <div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--color-text-muted)',
              marginBottom: 'var(--space-3)',
            }}
          >
            Source & Specs
          </div>
          <ul
            style={{
              listStyle: 'none',
              padding: 0,
              margin: 0,
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-2)',
            }}
          >
            <li>
              <a
                href="https://github.com/harshsingh2275/Bayora"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--color-primary)',
                  textDecoration: 'none',
                }}
              >
                Source Repository ↗
              </a>
            </li>
            <li>
              <a
                href="/api/openapi.json"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--color-text-secondary)',
                  textDecoration: 'none',
                }}
              >
                OpenAPI Specification ↗
              </a>
            </li>
            <li>
              <button
                type="button"
                onClick={() => onNavigate('threat')}
                style={{
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--color-text-secondary)',
                  cursor: 'pointer',
                  textAlign: 'left',
                }}
              >
                Formal Threat Model
              </button>
            </li>
            <li>
              <button
                type="button"
                onClick={() => onNavigate('data-handling')}
                style={{
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  fontFamily: 'var(--font-sans)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--color-text-secondary)',
                  cursor: 'pointer',
                  textAlign: 'left',
                }}
              >
                Data Handling & Privacy
              </button>
            </li>
          </ul>
        </div>
      </div>

      <div
        style={{
          maxWidth: '1440px',
          margin: 'var(--space-8) auto 0 auto',
          paddingTop: 'var(--space-4)',
          borderTop: '1px solid var(--color-border-subtle)',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 'var(--space-4)',
          fontSize: 'var(--text-xs)',
          fontFamily: 'var(--font-mono)',
          color: 'var(--color-text-muted)',
        }}
      >
        <div>Bayora · Adversarial AI Safety Infrastructure</div>
        <div>Non-repudiable audit trails · Sealed commit-reveal protocol</div>
      </div>
    </footer>
  );
};
