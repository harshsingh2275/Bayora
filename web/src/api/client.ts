import type {
  HealthResponse,
  CacheModeResponse,
  TopologyResponse,
  RunListResponse,
  RunDetailResponse,
  RunResultsResponse,
  OperatorRunItemResponse,
  AuditLogResponse,
  VerifyResponse,
  TamperResponse,
  BreakitReportResponse,
  TimingReportResponse,
  CreateRunRequest,
  CreateRunResponse,
  AbortRunResponse,
} from "../types/api";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string | null
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["X-Admin-Token"] = token;
  }

  const res = await fetch(path, { ...options, headers });

  if (!res.ok) {
    let detail = `Request failed with status ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson && errJson.detail) {
        detail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore json parse error
    }
    throw new ApiError(res.status, detail);
  }

  return res.json() as Promise<T>;
}

export const api = {
  getHealth(): Promise<HealthResponse> {
    return request<HealthResponse>("/api/health");
  },

  getCacheMode(): Promise<CacheModeResponse> {
    return request<CacheModeResponse>("/api/cache-mode");
  },

  setCacheMode(mode: "isolated" | "shared", token: string): Promise<CacheModeResponse> {
    return request<CacheModeResponse>(
      "/api/admin/cache-mode",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode }),
      },
      token
    );
  },

  getTopology(): Promise<TopologyResponse> {
    return request<TopologyResponse>("/api/topology");
  },

  getRuns(): Promise<RunListResponse> {
    return request<RunListResponse>("/api/runs");
  },

  getRunDetail(runId: string): Promise<RunDetailResponse> {
    return request<RunDetailResponse>(`/api/runs/${encodeURIComponent(runId)}`);
  },

  getRunResults(runId: string): Promise<RunResultsResponse> {
    return request<RunResultsResponse>(`/api/runs/${encodeURIComponent(runId)}/results`);
  },

  createRun(data: CreateRunRequest, token: string): Promise<CreateRunResponse> {
    return request<CreateRunResponse>(
      "/api/runs",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      },
      token
    );
  },

  abortRun(runId: string, token: string): Promise<AbortRunResponse> {
    return request<AbortRunResponse>(
      `/api/runs/${encodeURIComponent(runId)}/abort`,
      { method: "POST" },
      token
    );
  },

  getOperatorItem(
    runId: string,
    idx: number,
    token: string
  ): Promise<OperatorRunItemResponse> {
    return request<OperatorRunItemResponse>(
      `/api/admin/runs/${encodeURIComponent(runId)}/items/${idx}`,
      {},
      token
    );
  },

  /**
   * Safe, non-mutating credential validation using the fixed nonexistent run UUID.
   * Expects 404 with detail "Run not found" when token is valid.
   * Expects 401 on invalid/missing token, 403 on tenant tokens.
   */
  async validateAdminToken(token: string): Promise<boolean> {
    try {
      const res = await fetch("/api/admin/runs/00000000-0000-0000-0000-000000000000/items/0", {
        headers: { "X-Admin-Token": token, Accept: "application/json" },
      });
      if (res.status === 404) {
        const body = await res.json().catch(() => null);
        return body && body.detail === "Run not found";
      }
      return false;
    } catch {
      return false;
    }
  },

  getAuditLog(after?: number, limit = 100): Promise<AuditLogResponse> {
    const params = new URLSearchParams();
    if (after !== undefined) params.set("after", String(after));
    params.set("limit", String(limit));
    return request<AuditLogResponse>(`/api/log?${params.toString()}`);
  },

  verifyAuditLog(): Promise<VerifyResponse> {
    return request<VerifyResponse>("/api/verify");
  },

  runTamperChecks(): Promise<TamperResponse> {
    return request<TamperResponse>("/api/verify/tamper-demo");
  },

  runTamperTest(): Promise<TamperResponse> {
    return request<TamperResponse>("/api/verify/tamper-demo");
  },

  listRuns(): Promise<RunListResponse> {
    return request<RunListResponse>("/api/runs");
  },

  getRun(runId: string): Promise<RunDetailResponse> {
    return request<RunDetailResponse>(`/api/runs/${encodeURIComponent(runId)}`);
  },

  getOperatorRunItem(
    runId: string,
    idx: number,
    token: string
  ): Promise<OperatorRunItemResponse> {
    return request<OperatorRunItemResponse>(
      `/api/admin/runs/${encodeURIComponent(runId)}/items/${idx}`,
      {},
      token
    );
  },

  getBreakitReport(): Promise<BreakitReportResponse> {
    return request<BreakitReportResponse>("/api/breakit/latest");
  },

  getTimingReport(): Promise<TimingReportResponse> {
    return request<TimingReportResponse>("/api/experiments/timing/latest");
  },
};

export const apiClient = api;
