// API 类型与请求封装,与 Go 后端的 JSON 结构一一对应。

export interface Violation {
  field: string;
  message: string;
}

export interface SignatureResult {
  keyid: string;
  valid: boolean;
  reason?: string;
  field: string;
  index: number;
}

export interface VerifyResult {
  artifactName: string;
  artifactSha256: string;
  artifactSize: number;
  envelope: unknown;
  statement?: unknown;
  signature: {
    ok: boolean;
    results: SignatureResult[];
    payloadType?: string;
    error?: string;
  };
  issuer: {
    ok: boolean;
    keyid: string;
    owner?: string;
    field: string;
    message?: string;
  };
  digest: {
    ok: boolean;
    expected: string;
    actual: string;
    field: string;
    message?: string;
  };
  policy: {
    allow: boolean;
    violations: Violation[];
  };
  decision: "allow" | "deny";
}

export interface VerifyResponse {
  id: string;
  result: VerifyResult;
}

export interface Summary {
  id: string;
  createdAt: string;
  source: string;
  artifactName: string;
  artifactSha256: string;
  decision: "allow" | "deny";
}

export interface Record extends Summary {
  envelope: unknown;
  statement?: unknown;
  result: VerifyResult;
}

export interface Demo {
  name: string;
  desc: string;
  expect: "allow" | "deny";
}

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return body as T;
}

export const api = {
  demos: () => req<Demo[]>("/api/demos"),
  list: () => req<Summary[]>("/api/verifications"),
  get: (id: string) => req<Record>(`/api/verifications/${id}`),
  verifyDemo: (name: string) =>
    req<VerifyResponse>(`/api/demos/${encodeURIComponent(name)}/verify`, { method: "POST" }),
  verifyUpload: (artifact: File, envelope: File) => {
    const fd = new FormData();
    fd.append("artifact", artifact);
    fd.append("envelope", envelope);
    return req<VerifyResponse>("/api/verify", { method: "POST", body: fd });
  },
};
