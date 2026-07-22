export type ApiHealth = {
  ida: {
    connected: boolean;
    database?: string;
    writable?: boolean;
    protocol_version?: string;
    architecture?: string;
    bits?: number;
    endian?: string;
    error?: string;
  };
  llm: {
    configured: boolean;
    provider?: string;
    model?: string;
    base_url?: string;
    temperature?: number;
    max_tokens?: number;
    api_key_configured?: boolean;
    error?: string;
  };
  storage: {
    db_path: string;
    summary: Record<string, number>;
  };
};

export type HarnessRun = {
  id: string;
  mode: string;
  status: string;
  thread_id: string | null;
  report_id: string;
  answer: string;
  error: string;
  metadata_json: string;
  started_at: string;
  finished_at: string;
};

export type TraceEvent = {
  id: string;
  run_id: string;
  sequence: number;
  event_type: string;
  message: string;
  data_json: string;
  created_at: string;
};

export type HarnessRunDetail = HarnessRun & {
  trace_events: TraceEvent[];
};

export type ChatToolCall = {
  id: string;
  name: string;
  args: Record<string, unknown>;
};

export type ChatMessage = {
  id: string;
  role: "user" | "assistant" | "tool" | string;
  content: string;
  name?: string;
  tool_call_id?: string;
  tool_calls?: ChatToolCall[];
  status?: string;
};

export type ChatThread = {
  id: string;
  sample_id: string | null;
  title: string;
  created_at: string;
  updated_at: string;
};

export type ChatThreadMessages = {
  thread: ChatThread;
  messages: ChatMessage[];
};

export type AgentChatResponse = {
  run_id: string;
  status: string;
  thread_id: string;
  answer: string;
  error: string;
  messages: ChatMessage[];
};

export type ReportSummary = {
  id: string;
  status: string;
  scope: string;
  summary: string;
  report_path: string;
  created_at?: string;
  started_at: string;
  finished_at: string;
};

export type ReportDetail = {
  report_id: string;
  summary: string;
  scope: string;
  sample: {
    database: string;
    architecture: string;
    bits: number;
    endian: string;
  };
  routes: unknown[];
  source_candidates: unknown[];
  findings: Array<{
    finding_id: string;
    category: string;
    severity: string;
    confidence: number;
    verification_status: string;
    source: string;
    evidence: string[];
    sink: {
      loc: string;
      caller_name: string;
      sink_name: string;
      category?: string;
    };
  }>;
  candidate_findings: CandidateFinding[];
};

export type CandidateFinding = {
  candidate_id: string;
  status: "pending" | "verified" | "unverified" | "rejected";
  category: string;
  severity: string;
  confidence: number;
  sink_name: string;
  sink_ea: string;
  caller_name: string;
  caller_ea: string;
  callee_ea: string;
  arguments: Array<{
    index: number;
    expression: string;
    arg_type: string;
    taint_status: string;
    source_func: string;
    source_expr: string;
    reason: string;
  }>;
  evidence: string[];
  missing_evidence: string[];
  conclusion: string;
};

export type FunctionContext = {
  name: string;
  start_ea: string;
  end_ea: string;
  size: number;
  prototype: string;
  decompile_ok: boolean;
  pseudocode: string;
  decompile_error: string;
  callers: unknown[];
  callees: unknown[];
  imports_used: string[];
  string_records: unknown[];
};

export type FirmwareEndpoint = {
  endpoint: string;
  source_file: string;
  candidate: string;
};

export type FirmwareCandidate = {
  path: string;
  relative_path: string;
  size: number;
  elf_class: string;
  endian: string;
  machine: string;
  elf_type: string;
  score: number;
  rank: number;
  reasons: string[];
  route_markers: string[];
  source_markers: string[];
  sink_markers: string[];
  referenced_by: string[];
  web_references: string[];
  startup_references: string[];
  config_references: string[];
  web_endpoints: string[];
  ida_backend_command: string;
};

export type FirmwareTriageReport = {
  root: string;
  total_files: number;
  elf_files: number;
  text_files_scanned: number;
  web_endpoints: FirmwareEndpoint[];
  sensitive_files: string[];
  candidates: FirmwareCandidate[];
};

export type IntelQuery = {
  vendor: string;
  product: string;
  firmware_version: string;
  component: string;
  vulnerability_type: string;
  route: string;
  sink: string;
  symbols: string[];
  keywords: string[];
  max_results: number;
};

export type IntelReference = {
  source: "cveorg" | "nvd" | "github" | "manual";
  identifier: string;
  title: string;
  description: string;
  url: string;
  published: string;
  modified: string;
  severity: string;
  raw: Record<string, unknown>;
};

export type IntelMatch = {
  reference: IntelReference;
  score: number;
  confidence: "low" | "medium" | "high";
  reasons: string[];
  matched_terms: string[];
};

export type IntelSearchResult = {
  query: IntelQuery;
  matches: IntelMatch[];
  searched_sources: string[];
  errors: string[];
  assessment:
    | "likely_known_vulnerability"
    | "possible_known_vulnerability"
    | "no_strong_match"
    | "lookup_failed";
};
