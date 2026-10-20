import React from "react";
import { CheckIcon, CrossIcon, WarningIcon, InfoIcon } from "./Icons";

export type BadgeVariant = "pass" | "fail" | "warn" | "info";

interface StatusBadgeProps {
  variant?: BadgeVariant;
  label?: string;
  status?: string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  variant,
  label,
  status,
  className = "",
}) => {
  let resolvedVariant: BadgeVariant = variant || "info";
  let resolvedLabel: string = label || status || "";

  if (status) {
    const s = status.toLowerCase();
    if (["ok", "verified", "pass", "concluded", "no_leak_detected"].includes(s)) {
      resolvedVariant = "pass";
    } else if (["failed", "fail", "complied", "leak_detected", "aborted"].includes(s)) {
      resolvedVariant = "fail";
    } else if (["running", "committing", "created", "pending"].includes(s)) {
      resolvedVariant = "info";
    } else if (["blocked_input", "blocked_output", "refused", "error", "warn"].includes(s)) {
      resolvedVariant = "warn";
    }
  }

  const getIcon = () => {
    switch (resolvedVariant) {
      case "pass":
        return <CheckIcon size={13} />;
      case "fail":
        return <CrossIcon size={13} />;
      case "warn":
        return <WarningIcon size={13} />;
      case "info":
      default:
        return <InfoIcon size={13} />;
    }
  };

  const colors = {
    pass: {
      bg: "var(--color-status-pass-bg)",
      text: "var(--color-status-pass-text)",
    },
    fail: {
      bg: "var(--color-status-fail-bg)",
      text: "var(--color-status-fail-text)",
    },
    warn: {
      bg: "var(--color-status-warn-bg)",
      text: "var(--color-status-warn-text)",
    },
    info: {
      bg: "var(--color-status-info-bg)",
      text: "var(--color-status-info-text)",
    },
  }[resolvedVariant];

  return (
    <span
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "var(--space-1)",
        backgroundColor: colors.bg,
        color: colors.text,
        border: `1px solid ${colors.text}`,
        padding: "2px var(--space-2)",
        fontSize: "var(--font-size-xs)",
        fontWeight: "var(--font-weight-strong)",
        lineHeight: "1.2",
        verticalAlign: "middle",
        whiteSpace: "nowrap",
        textTransform: "uppercase",
        fontFamily: "var(--font-family-mono)",
      }}
    >
      {getIcon()}
      <span>{resolvedLabel}</span>
    </span>
  );
};
