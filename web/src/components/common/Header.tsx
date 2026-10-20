import React, { useState, useEffect } from "react";
import { useTheme } from "../../context/ThemeContext";
import { useAuth } from "../../context/AuthContext";
import { api } from "../../api/client";
import { SunIcon, MoonIcon, CheckIcon, WarningIcon, LockIcon } from "./Icons";

import type { ViewType } from "../../types/api";

interface HeaderProps {
  currentView?: ViewType;
  currentPath?: string;
  onNavigate: (view: ViewType) => void;
  onOpenLogin?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ currentView = "overview", currentPath: _currentPath, onNavigate, onOpenLogin }) => {
  const { theme, toggleTheme } = useTheme();
  const { isAuthenticated, logout, openLoginModal } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [healthOk, setHealthOk] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;
    const checkHealth = async () => {
      try {
        const res = await api.getHealth();
        if (mounted) {
          setHealthOk(res.status === "ok");
        }
      } catch {
        if (mounted) setHealthOk(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems: { label: string; view: ViewType; path: string }[] = [
    { label: "Overview", view: "overview", path: "/" },
    { label: "Runs", view: "runs", path: "/runs" },
    { label: "Audit log", view: "audit", path: "/audit" },
    { label: "Active probes", view: "breakit", path: "/breakit" },
    { label: "Timing", view: "timing", path: "/timing" },
    { label: "Threat model", view: "threat", path: "/threat-model" },
    { label: "Data handling", view: "data-handling", path: "/data-handling" },
  ];

  const handleNavClick = (view: ViewType) => {
    onNavigate(view);
    setMobileMenuOpen(false);
  };

  return (
    <header
      style={{
        borderBottom: "1px solid var(--color-border-divider)",
        backgroundColor: "var(--color-surface-panel)",
      }}
    >
      <div
        className="container"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          height: "64px",
          gap: "var(--space-4)",
        }}
      >
        {/* Brand wordmark */}
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-4)" }}>
          <button
            type="button"
            onClick={() => handleNavClick("overview")}
            className="font-display"
            style={{
              fontSize: "var(--font-size-xl)",
              textDecoration: "none",
              color: "var(--color-text-primary)",
              border: "none",
              padding: 0,
              background: "none",
              letterSpacing: "-0.01em",
            }}
          >
            Bayora
          </button>

          {/* Service health indicator */}
          <span
            className="header-health-badge"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              fontSize: "var(--font-size-xs)",
              fontWeight: "var(--font-weight-strong)",
              padding: "2px var(--space-2)",
              border: "1px solid var(--color-border-divider)",
              color:
                healthOk === true
                  ? "var(--color-status-pass-text)"
                  : healthOk === false
                  ? "var(--color-status-fail-text)"
                  : "var(--color-text-secondary)",
              backgroundColor:
                healthOk === true
                  ? "var(--color-status-pass-bg)"
                  : healthOk === false
                  ? "var(--color-status-fail-bg)"
                  : "var(--color-surface-sunken)",
            }}
          >
            {healthOk === true ? (
              <CheckIcon size={12} />
            ) : healthOk === false ? (
              <WarningIcon size={12} />
            ) : null}
            <span>{healthOk === true ? "Services healthy" : healthOk === false ? "Degraded" : "Checking"}</span>
          </span>
        </div>

        {/* Desktop Navigation */}
        <nav
          aria-label="Main navigation"
          style={{
            display: "none",
            alignItems: "center",
            gap: "var(--space-5)",
          }}
          className="desktop-nav"
        >
          {navItems.map((item) => {
            const isCurrent = currentView === item.view;
            return (
              <button
                key={item.view}
                type="button"
                onClick={() => handleNavClick(item.view)}
                aria-current={isCurrent ? "page" : undefined}
                style={{
                  color: isCurrent ? "var(--color-accent-primary)" : "var(--color-text-primary)",
                  border: "none",
                  background: "none",
                  fontWeight: isCurrent ? "var(--font-weight-strong)" : "var(--font-weight-base)",
                  textDecoration: "none",
                  borderBottom: isCurrent ? "2px solid var(--color-accent-primary)" : "2px solid transparent",
                  padding: "var(--space-2) 0",
                  height: "44px",
                  display: "inline-flex",
                  alignItems: "center",
                }}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Action Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", flexShrink: 0 }}>
          {/* Light/Dark Mode Toggle */}
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            style={{
              border: "1px solid var(--color-border-control)",
              padding: "var(--space-2)",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              color: "var(--color-text-primary)",
              background: "var(--color-surface-panel)",
              height: "36px",
              width: "36px",
            }}
          >
            {theme === "dark" ? <SunIcon size={16} /> : <MoonIcon size={16} />}
          </button>

          {/* Operator sign-in button or status */}
          {isAuthenticated ? (
            <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
              <span
                style={{
                  fontSize: "var(--font-size-xs)",
                  color: "var(--color-status-pass-text)",
                  backgroundColor: "var(--color-status-pass-bg)",
                  border: "1px solid var(--color-status-pass-text)",
                  padding: "2px var(--space-2)",
                  fontWeight: "var(--font-weight-strong)",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px",
                }}
              >
                <LockIcon size={12} />
                <span>Operator</span>
              </span>
              <button
                type="button"
                onClick={logout}
                style={{
                  border: "1px solid var(--color-border-control)",
                  padding: "2px var(--space-2)",
                  fontSize: "var(--font-size-xs)",
                  color: "var(--color-text-primary)",
                  background: "var(--color-surface-panel)",
                  height: "36px",
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
                border: "1px solid var(--color-border-control)",
                padding: "0 var(--space-2)",
                fontSize: "var(--font-size-xs)",
                fontWeight: "var(--font-weight-strong)",
                color: "var(--color-text-primary)",
                background: "var(--color-surface-panel)",
                height: "36px",
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
              }}
            >
              <LockIcon size={12} />
              <span>Operator</span>
            </button>
          )}

          {/* Mobile menu toggle button */}
          <button
            type="button"
            className="mobile-menu-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-expanded={mobileMenuOpen}
            aria-label="Toggle navigation menu"
            style={{
              border: "1px solid var(--color-border-control)",
              padding: "0 var(--space-3)",
              height: "36px",
              fontSize: "var(--font-size-xs)",
              fontWeight: "var(--font-weight-strong)",
              color: "var(--color-text-primary)",
              background: "var(--color-surface-panel)",
            }}
          >
            {mobileMenuOpen ? "Close" : "Menu"}
          </button>
        </div>
      </div>

      {/* Mobile navigation drawer */}
      {mobileMenuOpen && (
        <nav
          aria-label="Mobile navigation"
          style={{
            borderTop: "1px solid var(--color-border-divider)",
            backgroundColor: "var(--color-surface-panel)",
            padding: "var(--space-4)",
            display: "flex",
            flexDirection: "column",
            gap: "var(--space-2)",
          }}
        >
          {navItems.map((item) => {
            const isCurrent = currentView === item.view;
            return (
              <button
                key={item.view}
                type="button"
                onClick={() => handleNavClick(item.view)}
                aria-current={isCurrent ? "page" : undefined}
                style={{
                  textAlign: "left",
                  color: isCurrent ? "var(--color-accent-primary)" : "var(--color-text-primary)",
                  fontWeight: isCurrent ? "var(--font-weight-strong)" : "var(--font-weight-base)",
                  padding: "var(--space-2) var(--space-3)",
                  border: isCurrent ? "1px solid var(--color-accent-primary)" : "1px solid transparent",
                  backgroundColor: isCurrent ? "var(--color-surface-sunken)" : "transparent",
                  fontSize: "var(--font-size-sm)",
                }}
              >
                {item.label}
              </button>
            );
          })}
        </nav>
      )}

      <style>{`
        @media (min-width: 768px) {
          .desktop-nav {
            display: flex !important;
          }
          .mobile-menu-btn {
            display: none !important;
          }
        }
      `}</style>
    </header>
  );
};
