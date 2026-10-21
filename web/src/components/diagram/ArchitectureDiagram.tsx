import React, { useState, useEffect } from "react";
import type { TopologyResponse, TopologyService } from "../../types/api";
import { api } from "../../api/client";

interface ArchitectureDiagramProps {
  topology?: TopologyResponse | null;
  loading?: boolean;
}

const TRACE_STEPS = [
  {
    title: "1. Run Creation",
    description: "Operator initiates evaluation run; Gateway validates input schema and logs run_created to Logger.",
    activeNodes: ["web", "gateway", "logger"],
  },
  {
    title: "2. Input Commitment",
    description: "Red commits attack set digest; Blue commits defense bundle digest. Both logged before execution.",
    activeNodes: ["red", "blue", "gateway", "logger"],
  },
  {
    title: "3. Attack Processing",
    description: "Red sends prompt. Gateway checks commitment digest, applies Blue input rules, and routes to Model slot.",
    activeNodes: ["red", "gateway", "model"],
  },
  {
    title: "4. Defense & Scoring",
    description: "Gateway receives completion, applies Blue output rules, evaluates heuristic refusal markers, and seals record.",
    activeNodes: ["gateway", "model"],
  },
  {
    title: "5. Conclusion & Reveal",
    description: "Red signals done. Gateway computes results_digest, logs run_concluded, and reveals results safely.",
    activeNodes: ["gateway", "logger"],
  },
];

export const ArchitectureDiagram: React.FC<ArchitectureDiagramProps> = ({
  topology: propTopology,
  loading: propLoading = false,
}) => {
  const [internalTopology, setInternalTopology] = useState<TopologyResponse | null>(null);
  const [internalLoading, setInternalLoading] = useState(false);

  useEffect(() => {
    if (!propTopology) {
      let mounted = true;
      setInternalLoading(true);
      api.getTopology()
        .then((data) => {
          if (mounted) setInternalTopology(data);
        })
        .catch(() => {})
        .finally(() => {
          if (mounted) setInternalLoading(false);
        });
      return () => {
        mounted = false;
      };
    }
  }, [propTopology]);

  const topology = propTopology !== undefined ? propTopology : internalTopology;
  const loading = propLoading || (internalLoading && !topology);
  const [selectedNode, setSelectedNode] = useState<TopologyService | null>(null);
  const [traceStep, setTraceStep] = useState<number | null>(null);
  const [showList, setShowList] = useState(false);

  const services = topology?.services || [];

  const handleNodeClick = (name: string) => {
    const s = services.find((svc) => svc.name === name);
    setSelectedNode(s || null);
  };

  const isNodeActiveInTrace = (name: string) => {
    if (traceStep === null) return true;
    return TRACE_STEPS[traceStep].activeNodes.includes(name);
  };

  if (loading) {
    return (
      <div
        style={{
          padding: "var(--space-6)",
          textAlign: "center",
          backgroundColor: "var(--color-surface-panel)",
          border: "1px solid var(--color-border-divider)",
        }}
      >
        <p style={{ color: "var(--color-text-secondary)" }}>Loading topology architecture...</p>
      </div>
    );
  }

  return (
    <div
      style={{
        backgroundColor: "var(--color-surface-panel)",
        border: "1px solid var(--color-border-divider)",
        padding: "var(--space-4)",
      }}
    >
      {/* Header with Title and View Switcher */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "var(--space-3)",
          borderBottom: "1px solid var(--color-border-divider)",
          paddingBottom: "var(--space-2)",
        }}
      >
        <span
          style={{
            fontSize: "var(--font-size-xs)",
            fontWeight: "var(--font-weight-strong)",
            color: "var(--color-text-secondary)",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
          }}
        >
          System Topology & Boundaries (SI-01..SI-04)
        </span>
        <button
          type="button"
          onClick={() => setShowList(!showList)}
          style={{
            fontSize: "var(--font-size-xs)",
            color: "var(--color-accent-primary)",
            background: "none",
            border: "none",
            textDecoration: "underline",
          }}
        >
          {showList ? "Show diagram view" : "View as list"}
        </button>
      </div>

      {showList ? (
        /* Accessible List Representation */
        <div style={{ padding: "var(--space-3) 0" }}>
          <h3 style={{ fontSize: "var(--font-size-md)", marginBottom: "var(--space-3)" }}>
            Services and Isolation Boundaries
          </h3>
          <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
            {services.map((svc) => (
              <li
                key={svc.name}
                style={{
                  border: "1px solid var(--color-border-divider)",
                  padding: "var(--space-3)",
                  backgroundColor: "var(--color-surface-sunken)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "var(--space-1)" }}>
                  <strong className="font-mono">{svc.name}</strong>
                  <span style={{ fontSize: "var(--font-size-xs)", color: "var(--color-text-secondary)" }}>
                    {svc.image}
                  </span>
                </div>
                <p style={{ fontSize: "var(--font-size-sm)", marginBottom: "var(--space-2)" }}>
                  {svc.purpose}
                </p>
                <div style={{ fontSize: "var(--font-size-xs)", color: "var(--color-text-secondary)" }}>
                  Networks: {svc.networks.join(", ")} | TCB: {svc.tcb ? "Yes" : "No"} | Isolated: {svc.isolated ? "Yes" : "No"}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        /* Interactive SVG Architecture Diagram */
        <div>
          <svg
            viewBox="0 0 760 420"
            style={{
              width: "100%",
              height: "auto",
              display: "block",
              background: "var(--color-surface-base)",
              border: "1px solid var(--color-border-divider)",
            }}
            role="img"
            aria-label="Interactive system architecture diagram illustrating network isolation between tenants, gateway, model, and logger."
          >
            <defs>
              {/* Markers for blocked paths */}
              <marker
                id="marker-cross"
                markerWidth="8"
                markerHeight="8"
                refX="4"
                refY="4"
              >
                <line x1="1" y1="1" x2="7" y2="7" stroke="var(--color-status-fail-text)" strokeWidth="2" />
                <line x1="7" y1="1" x2="1" y2="7" stroke="var(--color-status-fail-text)" strokeWidth="2" />
              </marker>
            </defs>

            {/* Host Boundary */}
            <rect
              x="10"
              y="10"
              width="740"
              height="400"
              fill="none"
              stroke="var(--color-border-divider)"
              strokeWidth="1.5"
            />
            <text
              x="25"
              y="32"
              fill="var(--color-text-secondary)"
              fontSize="12"
              fontFamily="var(--font-family-primary)"
              fontWeight="600"
              letterSpacing="0.05em"
            >
              HOST ENVIRONMENT: LINUX VM (DOCKER COMPOSE HARDENED)
            </text>

            {/* Network Boundary: front-net (web + gateway) */}
            <rect
              x="30"
              y="45"
              width="150"
              height="350"
              fill="var(--color-surface-panel)"
              stroke="var(--color-border-divider)"
              strokeWidth="1"
            />
            <text x="40" y="65" fill="var(--color-text-secondary)" fontSize="11" fontWeight="600">
              front-net (Public)
            </text>

            {/* Network Boundary: Tenant Nets (red-net, blue-net) */}
            <rect
              x="195"
              y="45"
              width="170"
              height="168"
              fill="var(--color-surface-panel)"
              stroke="var(--color-border-divider)"
              strokeWidth="1"
            />
            <text x="205" y="65" fill="var(--color-text-secondary)" fontSize="11" fontWeight="600">
              red-net (Internal)
            </text>

            <rect
              x="195"
              y="227"
              width="170"
              height="168"
              fill="var(--color-surface-panel)"
              stroke="var(--color-border-divider)"
              strokeWidth="1"
            />
            <text x="205" y="247" fill="var(--color-text-secondary)" fontSize="11" fontWeight="600">
              blue-net (Internal)
            </text>

            {/* Network Boundary: Hub / Gateway */}
            <rect
              x="380"
              y="45"
              width="170"
              height="350"
              fill="var(--color-surface-panel)"
              stroke="var(--color-border-divider)"
              strokeWidth="1"
            />
            <text x="390" y="65" fill="var(--color-text-secondary)" fontSize="11" fontWeight="600">
              Gateway Hub (SI-04)
            </text>

            {/* Network Boundary: Model & Log Nets */}
            <rect
              x="565"
              y="45"
              width="170"
              height="168"
              fill="var(--color-surface-panel)"
              stroke="var(--color-border-divider)"
              strokeWidth="1"
            />
            <text x="575" y="65" fill="var(--color-text-secondary)" fontSize="11" fontWeight="600">
              model-nets (Internal)
            </text>

            <rect
              x="565"
              y="227"
              width="170"
              height="168"
              fill="var(--color-surface-panel)"
              stroke="var(--color-border-divider)"
              strokeWidth="1"
            />
            <text x="575" y="247" fill="var(--color-text-secondary)" fontSize="11" fontWeight="600">
              log-net (Internal)
            </text>

            {/* Blocked Communication Lines (Dashed Crimson with Crosses) */}
            {/* Red to Blue */}
            <line
              x1="280"
              y1="150"
              x2="280"
              y2="280"
              stroke="var(--color-status-fail-text)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
              markerEnd="url(#marker-cross)"
            />
            <text x="288" y="218" fill="var(--color-status-fail-text)" fontSize="10" fontWeight="600">
              Blocked
            </text>

            {/* Red to Model direct */}
            <path
              d="M 330 110 Q 460 30 600 100"
              fill="none"
              stroke="var(--color-status-fail-text)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
              markerEnd="url(#marker-cross)"
            />

            {/* Allowed Communication Lines (Solid Accent Lines) */}
            {/* Web -> Gateway */}
            <line
              x1="155"
              y1="220"
              x2="405"
              y2="220"
              stroke="var(--color-accent-primary)"
              strokeWidth="2"
            />
            <text x="260" y="214" fill="var(--color-text-secondary)" fontSize="10">
              /api/* only
            </text>

            {/* Red -> Gateway */}
            <line
              x1="330"
              y1="130"
              x2="405"
              y2="200"
              stroke="var(--color-accent-primary)"
              strokeWidth="2"
            />

            {/* Blue -> Gateway */}
            <line
              x1="330"
              y1="310"
              x2="405"
              y2="240"
              stroke="var(--color-accent-primary)"
              strokeWidth="2"
            />

            {/* Gateway -> Model */}
            <line
              x1="525"
              y1="200"
              x2="590"
              y2="130"
              stroke="var(--color-accent-primary)"
              strokeWidth="2"
            />

            {/* Gateway -> Logger */}
            <line
              x1="525"
              y1="240"
              x2="590"
              y2="285"
              stroke="var(--color-accent-primary)"
              strokeWidth="2"
            />

            {/* Logger -> Verifier (Read-only volume) */}
            <line
              x1="650"
              y1="310"
              x2="650"
              y2="340"
              stroke="var(--color-text-secondary)"
              strokeWidth="1.5"
              strokeDasharray="2 2"
            />

            {/* NODES (Buttons in SVG) */}

            {/* 1. Web Node */}
            <g
              onClick={() => handleNodeClick("web")}
              style={{ cursor: "pointer", opacity: isNodeActiveInTrace("web") ? 1 : 0.25 }}
            >
              <rect
                x="45"
                y="190"
                width="110"
                height="60"
                fill="var(--color-surface-sunken)"
                stroke={selectedNode?.name === "web" ? "var(--color-accent-primary)" : "var(--color-border-control)"}
                strokeWidth={selectedNode?.name === "web" ? "2.5" : "1.5"}
              />
              <text x="55" y="215" fill="var(--color-text-primary)" fontSize="13" fontWeight="600" fontFamily="var(--font-family-mono)">
                web (Caddy)
              </text>
              <text x="55" y="235" fill="var(--color-text-secondary)" fontSize="10">
                Port 8088 (SI-11)
              </text>
            </g>

            {/* 2. Red Node */}
            <g
              onClick={() => handleNodeClick("red")}
              style={{ cursor: "pointer", opacity: isNodeActiveInTrace("red") ? 1 : 0.25 }}
            >
              <rect
                x="215"
                y="100"
                width="115"
                height="60"
                fill="var(--color-surface-sunken)"
                stroke={selectedNode?.name === "red" ? "var(--color-accent-primary)" : "var(--color-border-control)"}
                strokeWidth={selectedNode?.name === "red" ? "2.5" : "1.5"}
              />
              <text x="225" y="125" fill="var(--color-text-primary)" fontSize="13" fontWeight="600" fontFamily="var(--font-family-mono)">
                red (Attacker)
              </text>
              <text x="225" y="145" fill="var(--color-text-secondary)" fontSize="10">
                UID 10001 (ro root)
              </text>
            </g>

            {/* 3. Blue Node */}
            <g
              onClick={() => handleNodeClick("blue")}
              style={{ cursor: "pointer", opacity: isNodeActiveInTrace("blue") ? 1 : 0.25 }}
            >
              <rect
                x="215"
                y="280"
                width="115"
                height="60"
                fill="var(--color-surface-sunken)"
                stroke={selectedNode?.name === "blue" ? "var(--color-accent-primary)" : "var(--color-border-control)"}
                strokeWidth={selectedNode?.name === "blue" ? "2.5" : "1.5"}
              />
              <text x="225" y="305" fill="var(--color-text-primary)" fontSize="13" fontWeight="600" fontFamily="var(--font-family-mono)">
                blue (Defender)
              </text>
              <text x="225" y="325" fill="var(--color-text-secondary)" fontSize="10">
                UID 10001 (ro root)
              </text>
            </g>

            {/* 4. Gateway Node (TCB Hub) */}
            <g
              onClick={() => handleNodeClick("gateway")}
              style={{ cursor: "pointer", opacity: isNodeActiveInTrace("gateway") ? 1 : 0.25 }}
            >
              <rect
                x="405"
                y="180"
                width="120"
                height="80"
                fill="var(--color-surface-sunken)"
                stroke={selectedNode?.name === "gateway" ? "var(--color-accent-primary)" : "var(--color-text-primary)"}
                strokeWidth={selectedNode?.name === "gateway" ? "3" : "2"}
              />
              <text x="415" y="210" fill="var(--color-text-primary)" fontSize="14" fontWeight="600" fontFamily="var(--font-family-mono)">
                gateway
              </text>
              <text x="415" y="230" fill="var(--color-text-secondary)" fontSize="10">
                FastAPI / Hub
              </text>
              <text x="415" y="246" fill="var(--color-status-pass-text)" fontSize="10" fontWeight="600">
                Sole Model Route
              </text>
            </g>

            {/* 5. Model Node */}
            <g
              onClick={() => handleNodeClick("model")}
              style={{ cursor: "pointer", opacity: isNodeActiveInTrace("model") ? 1 : 0.25 }}
            >
              <rect
                x="590"
                y="95"
                width="125"
                height="65"
                fill="var(--color-surface-sunken)"
                stroke={selectedNode?.name === "model" ? "var(--color-accent-primary)" : "var(--color-border-control)"}
                strokeWidth={selectedNode?.name === "model" ? "2.5" : "1.5"}
              />
              <text x="600" y="120" fill="var(--color-text-primary)" fontSize="13" fontWeight="600" fontFamily="var(--font-family-mono)">
                model (LLM Cluster)
              </text>
              <text x="600" y="140" fill="var(--color-text-secondary)" fontSize="10">
                model-red & model-blue
              </text>
              <text x="600" y="152" fill="var(--color-text-secondary)" fontSize="9">
                Tenant routed instances
              </text>
            </g>

            {/* 6. Logger Node */}
            <g
              onClick={() => handleNodeClick("logger")}
              style={{ cursor: "pointer", opacity: isNodeActiveInTrace("logger") ? 1 : 0.25 }}
            >
              <rect
                x="590"
                y="255"
                width="125"
                height="55"
                fill="var(--color-surface-sunken)"
                stroke={selectedNode?.name === "logger" ? "var(--color-accent-primary)" : "var(--color-border-control)"}
                strokeWidth={selectedNode?.name === "logger" ? "2.5" : "1.5"}
              />
              <text x="600" y="278" fill="var(--color-text-primary)" fontSize="13" fontWeight="600" fontFamily="var(--font-family-mono)">
                logger
              </text>
              <text x="600" y="296" fill="var(--color-text-secondary)" fontSize="10">
                Append-only ledger
              </text>
            </g>

            {/* 7. Verifier Node */}
            <g
              onClick={() => handleNodeClick("verifier")}
              style={{ cursor: "pointer", opacity: isNodeActiveInTrace("verifier") ? 1 : 0.25 }}
            >
              <rect
                x="590"
                y="330"
                width="125"
                height="55"
                fill="var(--color-surface-sunken)"
                stroke={selectedNode?.name === "verifier" ? "var(--color-accent-primary)" : "var(--color-border-control)"}
                strokeWidth={selectedNode?.name === "verifier" ? "2.5" : "1.5"}
              />
              <text x="600" y="353" fill="var(--color-text-primary)" fontSize="13" fontWeight="600" fontFamily="var(--font-family-mono)">
                verifier
              </text>
              <text x="600" y="371" fill="var(--color-text-secondary)" fontSize="10">
                Read-only mount
              </text>
            </g>
          </svg>

          {/* Trace Request Flow Bar */}
          <div
            style={{
              marginTop: "var(--space-3)",
              padding: "var(--space-3)",
              backgroundColor: "var(--color-surface-sunken)",
              border: "1px solid var(--color-border-divider)",
              display: "flex",
              flexDirection: "column",
              gap: "var(--space-2)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "var(--font-size-xs)", fontWeight: "var(--font-weight-strong)" }}>
                Trace an evaluation request:
              </span>
              <div style={{ display: "flex", gap: "var(--space-2)" }}>
                <button
                  type="button"
                  onClick={() => setTraceStep((prev) => (prev === null || prev === 0 ? TRACE_STEPS.length - 1 : prev - 1))}
                  style={{
                    border: "1px solid var(--color-border-control)",
                    padding: "2px var(--space-2)",
                    fontSize: "var(--font-size-xs)",
                    background: "var(--color-surface-panel)",
                  }}
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => setTraceStep((prev) => (prev === null || prev === TRACE_STEPS.length - 1 ? 0 : prev + 1))}
                  style={{
                    border: "1px solid var(--color-border-control)",
                    padding: "2px var(--space-2)",
                    fontSize: "var(--font-size-xs)",
                    background: "var(--color-surface-panel)",
                  }}
                >
                  Next
                </button>
                {traceStep !== null && (
                  <button
                    type="button"
                    onClick={() => setTraceStep(null)}
                    style={{
                      border: "1px solid var(--color-border-control)",
                      padding: "2px var(--space-2)",
                      fontSize: "var(--font-size-xs)",
                      background: "var(--color-surface-panel)",
                      color: "var(--color-text-secondary)",
                    }}
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {traceStep !== null ? (
              <div style={{ fontSize: "var(--font-size-xs)" }}>
                <strong>{TRACE_STEPS[traceStep].title}:</strong> {TRACE_STEPS[traceStep].description}
              </div>
            ) : (
              <p style={{ fontSize: "var(--font-size-xs)", color: "var(--color-text-secondary)" }}>
                Click Next to trace an evaluation request lifecycle through the isolated services. Click any service node to inspect its boundaries.
              </p>
            )}
          </div>

          {/* Node Detail Inspector */}
          {selectedNode && (
            <div
              style={{
                marginTop: "var(--space-3)",
                padding: "var(--space-3)",
                backgroundColor: "var(--color-surface-panel)",
                border: "1px solid var(--color-border-divider)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", marginBottom: "4px" }}>
                  <strong className="font-mono">{selectedNode.name}</strong>
                  <span style={{ fontSize: "var(--font-size-xs)", color: "var(--color-text-secondary)" }}>
                    ({selectedNode.image})
                  </span>
                </div>
                <p style={{ fontSize: "var(--font-size-sm)", marginBottom: "var(--space-2)" }}>
                  {selectedNode.purpose}
                </p>
                <div style={{ fontSize: "var(--font-size-xs)", color: "var(--color-text-secondary)" }}>
                  Attached Networks: <strong>{selectedNode.networks.join(", ")}</strong> | TCB:{" "}
                  <strong>{selectedNode.tcb ? "Yes" : "No"}</strong> | Network Isolated:{" "}
                  <strong>{selectedNode.isolated ? "Yes (no external route)" : "Hub"}</strong>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                style={{
                  border: "1px solid var(--color-border-control)",
                  padding: "2px var(--space-2)",
                  fontSize: "var(--font-size-xs)",
                }}
              >
                Close
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
