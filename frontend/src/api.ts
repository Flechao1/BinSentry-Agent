import type {
  AgentChatResponse,
  ApiHealth,
  ChatThread,
  ChatThreadMessages,
  FunctionContext,
  HarnessRun,
  HarnessRunDetail,
  ReportDetail,
  ReportSummary
} from "./types";

const API_BASE = import.meta.env.VITE_VULNAGENT_API_BASE ?? "http://127.0.0.1:8787";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<ApiHealth>("/api/health"),
  runs: () => request<HarnessRun[]>("/api/harness/runs?limit=12"),
  run: (id: string) => request<HarnessRunDetail>(`/api/harness/runs/${id}`),
  reports: () => request<ReportSummary[]>("/api/reports?limit=20"),
  report: (id: string) => request<ReportDetail>(`/api/reports/${id}`),
  chats: () => request<ChatThread[]>("/api/chats?limit=20"),
  chatMessages: (threadId: string) => request<ChatThreadMessages>(`/api/chats/${threadId}/messages`),
  functionContext: (ea: string) => request<FunctionContext>(`/api/functions/${ea}/context`),
  chat: (prompt: string, threadId = "") =>
    request<AgentChatResponse>(
      "/api/agent/chat",
      {
        method: "POST",
        body: JSON.stringify({ prompt, thread_id: threadId, new_thread: !threadId })
      }
    ),
  scan: (threadId = "") =>
    request<{ run_id: string; status: string; thread_id: string; report_id: string; answer: string; error: string }>(
      "/api/baseline/scan",
      {
        method: "POST",
        body: JSON.stringify({ thread_id: threadId, new_thread: !threadId })
      }
    )
};
