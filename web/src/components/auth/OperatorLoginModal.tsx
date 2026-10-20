import React, { useState } from "react";
import { useAuth } from "../../context/AuthContext";
import { Modal } from "../common/Modal";

interface OperatorLoginModalProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const OperatorLoginModal: React.FC<OperatorLoginModalProps> = ({
  isOpen: propIsOpen,
  onClose: propOnClose,
}) => {
  const { isLoginModalOpen, closeLoginModal, login } = useAuth();
  const [tokenInput, setTokenInput] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const effectiveIsOpen = propIsOpen !== undefined ? propIsOpen : isLoginModalOpen;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokenInput.trim()) {
      setError("Please enter the operator token.");
      return;
    }
    setError(null);
    setLoading(true);

    try {
      const ok = await login(tokenInput);
      if (ok) {
        setTokenInput("");
        if (propOnClose) propOnClose();
        closeLoginModal();
      } else {
        setError("That token was not accepted.");
      }
    } catch {
      setError("Authentication service unavailable. Please retry.");
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setTokenInput("");
    setError(null);
    if (propOnClose) propOnClose();
    closeLoginModal();
  };

  return (
    <Modal
      isOpen={effectiveIsOpen}
      onClose={handleClose}
      title="Operator Sign-in"
      maxWidth="480px"
    >
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: "var(--space-4)" }}>
          <label
            htmlFor="admin-token-input"
            style={{
              display: "block",
              fontWeight: "var(--font-weight-strong)",
              marginBottom: "var(--space-2)",
            }}
          >
            Admin token
          </label>
          <div style={{ display: "flex", gap: "var(--space-2)" }}>
            <input
              id="admin-token-input"
              type={showToken ? "text" : "password"}
              value={tokenInput}
              onChange={(e) => {
                setTokenInput(e.target.value);
                if (error) setError(null);
              }}
              style={{ flex: 1, fontFamily: "var(--font-family-mono)" }}
              autoComplete="off"
              spellCheck="false"
              placeholder="Paste 32-byte hex token"
              disabled={loading}
              aria-describedby="token-help token-error"
            />
            <button
              type="button"
              onClick={() => setShowToken(!showToken)}
              style={{
                border: "1px solid var(--color-border-control)",
                padding: "0 var(--space-3)",
                fontSize: "var(--font-size-xs)",
                fontWeight: "var(--font-weight-strong)",
                background: "var(--color-surface-panel)",
                color: "var(--color-text-primary)",
              }}
            >
              {showToken ? "Hide" : "Show"}
            </button>
          </div>
          <p
            id="token-help"
            style={{
              fontSize: "var(--font-size-xs)",
              color: "var(--color-text-secondary)",
              marginTop: "var(--space-2)",
            }}
          >
            Held in memory only. Cleared when you reload or close the tab.
          </p>
          {error && (
            <p
              id="token-error"
              role="alert"
              style={{
                color: "var(--color-status-fail-text)",
                backgroundColor: "var(--color-status-fail-bg)",
                border: "1px solid var(--color-status-fail-text)",
                padding: "var(--space-2) var(--space-3)",
                fontSize: "var(--font-size-xs)",
                marginTop: "var(--space-3)",
                fontWeight: "var(--font-weight-strong)",
              }}
            >
              {error}
            </p>
          )}
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            gap: "var(--space-3)",
            marginTop: "var(--space-5)",
          }}
        >
          <button
            type="button"
            className="btn-secondary"
            onClick={handleClose}
            disabled={loading}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn-primary"
            disabled={loading}
          >
            {loading ? "Checking token..." : "Sign in"}
          </button>
        </div>
      </form>
    </Modal>
  );
};
