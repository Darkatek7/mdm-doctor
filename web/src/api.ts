import type {
  Application,
  ApplicationPage,
  Artifact,
  ComparisonSummary,
  CoverageRecord,
  EspResource,
  EvidenceLink,
  ExecutionAttempt,
  Finding,
  FindingPage,
  JobView,
  Kpis,
  ManagedEntity,
  EntityPage,
  ParseWarning,
  PreviewResponse,
  ProvisioningStep,
  PublicLimits,
  Session,
  Summary,
  TimelineEvent,
  TimelinePage,
} from "./generated-api";

export type {
  Application,
  ApplicationPage,
  Artifact,
  EspResource,
  EvidenceLink,
  Finding,
  FindingPage,
  JobView,
  Kpis,
  ParseWarning,
  ProvisioningStep,
  Session,
  Summary,
  TimelineEvent,
  TimelinePage,
  EntityPage,
};

export const JOB_HEADER = "X-MDM-Job-Handle";
export const COMPARE_HEADER = "X-MDM-Compare-Handle";
export const REDACTION_HEADER = "X-MDM-Redaction-Mode";

export type RedactionMode = "redacted" | "original";

export type Attempt = ExecutionAttempt;
export type Entity = ManagedEntity;
export type Coverage = CoverageRecord;
export type Comparison = ComparisonSummary;
export type Limits = PublicLimits;
export type Preview = PreviewResponse;

export class ApiError extends Error {
  constructor(public status:number, message:string) { super(message); }
}

export async function api<T>(path:string, handle:string, redaction:RedactionMode, init:RequestInit = {}):Promise<T> {
  const headers = new Headers(init.headers);
  headers.set(JOB_HEADER, handle);
  headers.set(REDACTION_HEADER, redaction);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...init, headers, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
  if (!response.ok) throw new ApiError(response.status, await safeError(response));
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function safeError(response:Response):Promise<string> {
  try { const value = await response.json() as {message?:string}; return value.message ?? "The operation failed safely."; }
  catch { return "The operation failed safely."; }
}

export function downloadBlob(blob:Blob, filename:string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noreferrer";
  anchor.click();
  queueMicrotask(() => URL.revokeObjectURL(url));
}
