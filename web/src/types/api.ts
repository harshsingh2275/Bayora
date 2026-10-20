/**
 * TypeScript API contracts matching gateway/app/models.py and OpenAPI spec
 */

export interface HealthResponse {
  status: string;
  services: {
    gateway: string;
    model: string;
    logger: string;
    verifier: string;
  };
}

export interface CacheModeResponse {
  mode: "isolated" | "shared";
}

export interface TopologyService {
  name: string;
  image: string;
  networks: string[];
  purpose: string;
  tcb: boolean;
  isolated: boolean;
}

export interface TopologyNetwork {
  name: string;
  internal: boolean;
  description: string;
  services: string[];
}

export interface TopologyResponse {
  services: TopologyService[];
  networks: TopologyNetwork[];
  invariants: string[];
}

export interface RunListItem {
  run_id: string;
  name: string;
  state: "created" | "committing" | "running" | "concluded" | "aborted" | "failed";
  attack_count: number;
  seed: number;
  bundle_name: string;
  created_at: string;
  updated_at: string;
  red_committed: boolean;
  blue_committed: boolean;
  set_digest: string | null;
  bundle_digest: string | null;
}

export interface RunListResponse {
  runs: RunListItem[];
}

export type RunDetailResponse = RunListItem;

export interface AttackResult {
  idx: number;
  latency_ms: number;
  outcome: "blocked_input" | "blocked_output" | "refused" | "complied" | "error";
  prompt_digest: string;
  prompt_preview: string;
}

export interface RunResultsResponse {
  run_id: string;
  total: number;
  aggregate: {
    blocked_input: number;
    blocked_output: number;
    complied: number;
    error: number;
    refused: number;
  };
  asr: number;
  attacks: AttackResult[];
}

export interface OperatorRunItemResponse {
  run_id: string;
  idx: number;
  prompt: string;
  response_text: string;
  outcome: string;
  rule_id: string | null;
  latency_ms: number | null;
}

export interface AuditLogEntry {
  seq: number;
  ts: string;
  run_id: string | null;
  actor: string;
  event: string;
  data: Record<string, unknown>;
  prev: string;
  hash: string;
}

export interface AuditLogResponse {
  entries: AuditLogEntry[];
}

export interface VerifyResponse {
  ok: boolean;
  entries: number;
  checkpoints: number;
  head: {
    seq: number;
    hash: string;
  };
  errors: string[];
}

export interface TamperCase {
  id: string;
  description: string;
  detected: boolean;
  expected_detection: boolean;
  passed: boolean;
  details: string;
  limitation?: boolean;
}

export interface TamperResponse {
  ok: boolean;
  cases: TamperCase[];
  summary: {
    total: number;
    passed: number;
    limitations_acknowledged: number;
    all_expectations_met: boolean;
  };
}

export interface BreakitProbe {
  id: string;
  category: "Network" | "Filesystem" | "Privilege" | "Authorization" | "Log" | "Config" | string;
  description: string;
  expected: string;
  observed: string;
  passed: boolean;
}

export interface BreakitReportResponse {
  generated_at: string;
  git_commit: string;
  probes: BreakitProbe[];
  summary: {
    total: number;
    passed: number;
    failed: number;
  };
}

export interface TimingModeStats {
  auc: number;
  mann_whitney_u: number;
  mean_hit_ms: number;
  mean_miss_ms: number;
  median_diff_ms: number;
  median_hit_ms: number;
  median_miss_ms: number;
  n_hit: number;
  n_miss: number;
  p_value: number;
  verdict: "leak_detected" | "no_leak_detected";
}

export interface TimingReportResponse {
  generated_at: string;
  git_commit: string;
  environment: {
    cpu_count?: number;
    llamacpp_version?: string;
    model_file?: string;
    model_parallel?: string;
    model_threads?: string;
    platform?: string;
    python_version?: string;
    [key: string]: unknown;
  };
  protocol: {
    attacker_max_tokens?: number;
    n_trials_per_condition?: number;
    prefix_words?: number;
    seed?: number;
    timing_method?: string;
    victim_max_tokens?: number;
    warmup_count?: number;
    [key: string]: unknown;
  };
  modes: {
    isolated: TimingModeStats;
    shared: TimingModeStats;
  };
  verdict: string;
  verdict_rule: string;
  raw_samples: {
    isolated: {
      hit: number[];
      miss: number[];
    };
    shared: {
      hit: number[];
      miss: number[];
    };
  };
  summary: Record<string, unknown>;
  limitations: string[];
}

export interface CreateRunRequest {
  name: string;
  attack_count: number;
  seed: number;
  bundle: "baseline" | "hardened";
}

export interface CreateRunResponse {
  run_id: string;
  state: string;
}

export interface AbortRunResponse {
  run_id: string;
  state: string;
}

export type ViewType =
  | 'overview'
  | 'runs'
  | 'audit'
  | 'breakit'
  | 'timing'
  | 'threat'
  | 'data-handling';
