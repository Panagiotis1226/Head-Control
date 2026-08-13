// Fetch wrapper for the Head-Control backend: base-path aware (via
// <base href>), CSRF header on mutations, unified error envelope.

import type { ApiErrorBody } from "./types";

// The backend rewrites <base href> at startup, so the app works under any
// BASE_PATH. All API URLs are resolved against it.
const apiBase = new URL(".", document.baseURI).pathname.replace(/\/$/, "");

let csrfToken = "";
export function setCsrfToken(token: string) {
  csrfToken = token;
}

/** Raised for every non-2xx API response. */
export class ApiError extends Error {
  status: number;
  code: string;
  headscaleMessage?: string;
  body?: ApiErrorBody;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.error?.message || fallback);
    this.status = status;
    this.code = body?.error?.code ?? "unknown";
    this.headscaleMessage = body?.error?.headscaleMessage;
    this.body = body ?? undefined;
  }
}

/** True when the UI session is gone (needs re-login). */
export function isSessionExpired(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401 && err.code === "unauthenticated";
}

type Listener = () => void;
const sessionExpiredListeners: Listener[] = [];
export function onSessionExpired(fn: Listener) {
  sessionExpiredListeners.push(fn);
}

export async function api<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = csrfToken;

  let resp: Response;
  try {
    resp = await fetch(apiBase + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
  } catch (e) {
    throw new ApiError(0, null, "cannot reach the Head-Control server — is it running?");
  }

  if (resp.ok) {
    if (resp.status === 204) return undefined as T;
    return (await resp.json()) as T;
  }

  let parsed: ApiErrorBody | null = null;
  try {
    parsed = (await resp.json()) as ApiErrorBody;
  } catch {
    // Non-JSON body (misconfigured proxy etc.) — fall through with fallback text.
  }
  const err = new ApiError(
    resp.status,
    parsed,
    `unexpected ${resp.status} response from the server — check your reverse proxy configuration`,
  );
  if (isSessionExpired(err)) sessionExpiredListeners.forEach((fn) => fn());
  throw err;
}

export const get = <T>(path: string) => api<T>("GET", path);
export const post = <T>(path: string, body?: unknown) => api<T>("POST", path, body);
export const put = <T>(path: string, body?: unknown) => api<T>("PUT", path, body);
export const del = <T>(path: string) => api<T>("DELETE", path);
