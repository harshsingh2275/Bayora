import React from "react";

interface SkipLinkProps {
  targetId?: string;
}

export const SkipLink: React.FC<SkipLinkProps> = ({ targetId = "main-content" }) => {
  return (
    <a
      href={`#${targetId}`}
      style={{
        position: "absolute",
        left: "-9999px",
        top: "auto",
        width: "1px",
        height: "1px",
        overflow: "hidden",
        zIndex: 9999,
        background: "var(--color-text-primary)",
        color: "var(--color-text-on-inverse)",
        padding: "var(--space-3) var(--space-4)",
        fontWeight: "var(--font-weight-strong)",
        textDecoration: "none",
      }}
      onFocus={(e) => {
        e.currentTarget.style.left = "var(--space-4)";
        e.currentTarget.style.top = "var(--space-4)";
        e.currentTarget.style.width = "auto";
        e.currentTarget.style.height = "auto";
      }}
      onBlur={(e) => {
        e.currentTarget.style.left = "-9999px";
        e.currentTarget.style.width = "1px";
        e.currentTarget.style.height = "1px";
      }}
    >
      Skip to content
    </a>
  );
};
