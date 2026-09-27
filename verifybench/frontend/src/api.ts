import type {
  DemoScenario,
  HealthResponse,
  ListResponse,
  TrustRoot,
  VerificationRecord,
} from './types'

async function asJSON<T>(res: Response): Promise<T> {
  const text = await res.text()
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    /* keep non-JSON error text */
  }
  if (!res.ok) {
    const msg =
      body && typeof body === 'object' && 'error' in (body as Record<string, unknown>)
        ? String((body as { error: unknown }).error)
        : `HTTP ${res.status}`
    throw new Error(msg)
  }
  return body as T
}

export const api = {
  async health(): Promise<HealthResponse> {
    const res = await fetch('/api/health')
    return asJSON<HealthResponse>(res)
  },

  async policy(): Promise<string> {
    const res = await fetch('/api/policy')
    const data = await asJSON<{ rego: string }>(res)
    return data.rego
  },

  async trustRoot(): Promise<TrustRoot> {
    const res = await fetch('/api/trust-root')
    return asJSON<TrustRoot>(res)
  },

  async demos(): Promise<DemoScenario[]> {
    const res = await fetch('/api/demo')
    const data = await asJSON<{ scenarios: DemoScenario[] }>(res)
    return data.scenarios
  },

  async verifyDemo(id: string): Promise<VerificationRecord> {
    const res = await fetch(`/api/verify/demo/${encodeURIComponent(id)}`, {
      method: 'POST',
    })
    return asJSON<VerificationRecord>(res)
  },

  async verifyUpload(artifact: File, envelope: File): Promise<VerificationRecord> {
    const form = new FormData()
    form.append('artifact', artifact, artifact.name)
    form.append('envelope', envelope, envelope.name)
    const res = await fetch('/api/verify', { method: 'POST', body: form })
    return asJSON<VerificationRecord>(res)
  },

  async list(limit = 50, offset = 0): Promise<ListResponse> {
    const res = await fetch(`/api/verifications?limit=${limit}&offset=${offset}`)
    return asJSON<ListResponse>(res)
  },

  async get(id: string): Promise<VerificationRecord> {
    const res = await fetch(`/api/verifications/${encodeURIComponent(id)}`)
    return asJSON<VerificationRecord>(res)
  },

  artifactURL(id: string): string {
    return `/api/verifications/${encodeURIComponent(id)}/artifact`
  },

  demoArtifactURL(id: string): string {
    return `/api/demo/${encodeURIComponent(id)}/artifact`
  },

  demoEnvelopeURL(id: string): string {
    return `/api/demo/${encodeURIComponent(id)}/envelope`
  },
}
