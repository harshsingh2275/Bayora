import React, { useState, useEffect } from "react";
import { useAuth } from "../../context/AuthContext";
import { api } from "../../api/client";
import type { ViewType } from "../../types/api";

interface HeaderProps {
  currentView?: ViewType;
  onNavigate: (view: ViewType) => void;
  onOpenLogin?: () => void;
}

const navItems: { label: string; view: ViewType }[] = [
  { label: "Overview", view: "overview" },
  { label: "Evaluation Runs", view: "runs" },
  { label: "Audit Verifier", view: "audit" },
  { label: "Isolation Probes", view: "breakit" },
  { label: "Timing Analysis", view: "timing" },
  { label: "Threat Model", view: "threat" },
  { label: "Privacy", view: "data-handling" },
];

// Hamburger icon
const MenuIcon: React.FC<{ open: boolean }> = ({ open }) => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
    {open ? (
      <>
        <line x1="4" y1="4" x2="16" y2="16" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
        <line x1="16" y1="4" x2="4" y2="16" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
      </>
    ) : (
      <>
        <line x1="3" y1="6" x2="17" y2="6" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
        <line x1="3" y1="10" x2="17" y2="10" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
        <line x1="3" y1="14" x2="17" y2="14" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
      </>
    )}
  </svg>
);

const LockIcon = () => (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <rect x="3" y="7" width="10" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
    <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

export const Header: React.FC<HeaderProps> = ({ currentView = "overview", onNavigate, onOpenLogin }) => {
  const { isAuthenticated, logout, openLoginModal } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [healthOk, setHealthOk] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;
    const checkHealth = async () => {
      try {
        const res = await api.getHealth();
        if (mounted) setHealthOk(res.status === "ok");
      } catch {
        if (mounted) setHealthOk(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  const handleNavClick = (view: ViewType) => {
    onNavigate(view);
    setMobileMenuOpen(false);
  };

  return (
    <>
      <header
        style={{
          position: "sticky",
          top: 0,
          zIndex: 50,
          background: "rgba(244, 242, 236, 0.92)",
          backdropFilter: "blur(8px)",
          WebkitBackdropFilter: "blur(8px)",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div
          className="container"
          style={{
            display: "flex",
            alignItems: "center",
            height: "var(--nav-height)",
            gap: "var(--space-5)",
          }}
        >
          {/* Brand wordmark */}
          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)", flexShrink: 0 }}>
            <button
              type="button"
              onClick={() => handleNavClick("overview")}
              style={{
                fontFamily: "var(--font-display)",
                fontSize: "1.4rem",
                color: "var(--text-primary)",
                border: "none",
                background: "none",
                padding: 0,
                cursor: "pointer",
                letterSpacing: "-0.01em",
                fontWeight: 400,
              }}
              aria-label="Bayora home"
            >
              Bayora
            </button>

            {/* Health badge — hidden below 600px via CSS class */}
            <span
              className="header-health-badge"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "5px",
                padding: "3px 8px",
                borderRadius: "var(--radius-pill)",
                background: healthOk === true
                  ? "var(--status-pass-bg)"
                  : healthOk === false
                    ? "var(--status-fail-bg)"
                    : "var(--bg-subtle)",
                border: `1px solid ${healthOk === true
                  ? "var(--status-pass-border)"
                  : healthOk === false
                    ? "var(--status-fail-border)"
                    : "var(--border-subtle)"}`,
                color: healthOk === true
                  ? "var(--status-pass-text)"
                  : healthOk === false
                    ? "var(--status-fail-text)"
                    : "var(--text-muted)",
                fontSize: "0.7rem",
                fontFamily: "var(--font-mono)",
                fontWeight: 600,
                whiteSpace: "nowrap",
              }}
            >
              {healthOk === true && (
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: "var(--status-pass-text)",
                    animation: "pulse-dot 2s ease-in-out infinite",
                    flexShrink: 0,
                  }}
                />
              )}
              {healthOk === true
                ? "Services Healthy"
                : healthOk === false
                  ? "Degraded"
                  : "Checking…"}
            </span>
          </div>

          {/* Desktop Navigation — shown ≥ 960px */}
          <nav
            className="desktop-nav"
            aria-label="Main navigation"
            style={{
              display: "none",
              alignItems: "center",
              gap: "2px",
              flex: 1,
            }}
          >
            {navItems.map((item) => {
              const active = currentView === item.view;
              return (
                <button
                  key={item.view}
                  type="button"
                  onClick={() => handleNavClick(item.view)}
                  aria-current={active ? "page" : undefined}
                  style={{
                    position: "relative",
                    padding: "6px 10px",
                    border: "none",
                    background: active ? "rgba(46,74,54,0.08)" : "none",
                    borderRadius: "var(--radius-sm)",
                    color: active ? "var(--accent-primary)" : "var(--text-secondary)",
                    fontSize: "0.82rem",
                    fontWeight: active ? 600 : 400,
                    fontFamily: "var(--font-sans)",
                    cursor: "pointer",
                    whiteSpace: "nowrap",
                    transition: "background var(--motion-fast), color var(--motion-fast)",
                  }}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Spacer on desktop so operator button stays right */}
          <div className="desktop-nav" style={{ flex: "none", display: "none" }} />

          {/* Right actions */}
          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", marginLeft: "auto", flexShrink: 0 }}>
            {/* Operator status / sign-in */}
            {isAuthenticated ? (
              <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 4,
                    fontSize: "0.72rem",
                    fontFamily: "var(--font-mono)",
                    fontWeight: 600,
                    color: "var(--status-pass-text)",
                    background: "var(--status-pass-bg)",
                    border: "1px solid var(--status-pass-border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "3px 8px",
                  }}
                >
                  <LockIcon /> Operator
                </span>
                <button
                  type="button"
                  onClick={logout}
                  style={{
                    height: 32,
                    padding: "0 10px",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "var(--radius-sm)",
                    fontSize: "0.75rem",
                    fontFamily: "var(--font-sans)",
                    color: "var(--text-secondary)",
                    background: "transparent",
                    cursor: "pointer",
                  }}
                >
                  Sign out
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={onOpenLogin || openLoginModal}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  height: 32,
                  padding: "0 10px",
                  border: "1px solid var(--border-strong)",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "0.75rem",
                  fontFamily: "var(--font-sans)",
                  fontWeight: 600,
                  color: "var(--text-primary)",
                  background: "transparent",
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                }}
              >
                <LockIcon />
                Operator
              </button>
            )}

            {/* Hamburger — shown < 960px */}
            <button
              type="button"
              className="mobile-menu-btn"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-expanded={mobileMenuOpen}
              aria-label="Toggle navigation menu"
              style={{
                display: "none",
                alignItems: "center",
                justifyContent: "center",
                height: 36,
                width: 36,
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                color: "var(--text-primary)",
                background: "transparent",
                cursor: "pointer",
              }}
            >
              <MenuIcon open={mobileMenuOpen} />
            </button>
          </div>
        </div>

        {/* Mobile drawer */}
        {mobileMenuOpen && (
          <nav
            aria-label="Mobile navigation"
            style={{
              borderTop: "1px solid var(--border-subtle)",
              background: "rgba(244, 242, 236, 0.98)",
              padding: "var(--space-3) var(--space-4) var(--space-5)",
              display: "flex",
              flexDirection: "column",
              gap: "var(--space-1)",
            }}
          >
            {navItems.map((item) => {
              const active = currentView === item.view;
              return (
                <button
                  key={item.view}
                  type="button"
                  onClick={() => handleNavClick(item.view)}
                  aria-current={active ? "page" : undefined}
                  style={{
                    textAlign: "left",
                    padding: "var(--space-3) var(--space-3)",
                    border: "none",
                    borderRadius: "var(--radius-sm)",
                    background: active ? "rgba(46,74,54,0.08)" : "transparent",
                    color: active ? "var(--accent-primary)" : "var(--text-primary)",
                    fontWeight: active ? 600 : 400,
                    fontSize: "var(--text-sm)",
                    fontFamily: "var(--font-sans)",
                    cursor: "pointer",
                  }}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>
        )}
      </header>
    </>
  );
};
