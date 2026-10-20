import React, { useState } from "react";
import { CopyIcon, CheckIcon } from "./Icons";

interface HashDisplayProps {
  hash: string | null | undefined;
  truncate?: boolean;
  truncateLength?: number;
  copyable?: boolean;
  className?: string;
}

export const HashDisplay: React.FC<HashDisplayProps> = ({
  hash,
  truncate = true,
  truncateLength = 8,
  copyable = true,
  className = "",
}) => {
  const [copied, setCopied] = useState(false);

  if (!hash) {
    return <span style={{ color: "var(--color-text-secondary)" }}>None</span>;
  }

  const len = truncateLength;
  const displayValue =
    truncate && hash.length > len * 2
      ? `${hash.slice(0, len)}...${hash.slice(-Math.min(6, len))}`
      : hash;

  const handleCopy = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(hash);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch {
      // fallback
    }
  };

  return (
    <span
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        flexWrap: "wrap",
        maxWidth: "100%",
        gap: "var(--space-2)",
        fontFamily: "var(--font-family-mono)",
        fontSize: "var(--font-size-mono)",
      }}
    >
      <code
        title={hash}
        style={{
          background: "var(--color-surface-sunken)",
          padding: "2px var(--space-1)",
          border: "1px solid var(--color-border-divider)",
          wordBreak: "break-all",
          maxWidth: "100%",
        }}
      >
        {displayValue}
      </code>
      {copyable && (
        <button
          type="button"
          onClick={handleCopy}
          aria-label={`Copy hash ${hash}`}
          style={{
            border: "1px solid var(--color-border-control)",
            background: copied ? "var(--color-status-pass-bg)" : "var(--color-surface-panel)",
            color: copied ? "var(--color-status-pass-text)" : "var(--color-text-primary)",
            padding: "2px 6px",
            fontSize: "var(--font-size-xs)",
            display: "inline-flex",
            alignItems: "center",
            gap: "4px",
            cursor: "pointer",
          }}
        >
          {copied ? <CheckIcon size={12} /> : <CopyIcon size={12} />}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      )}
      <span className="sr-only" aria-live="polite">
        {copied ? "Hash copied to clipboard" : ""}
      </span>
    </span>
  );
};
