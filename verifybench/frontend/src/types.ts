// Shared API types mirrored from the Go backend.

export interface SigResult {
  keyId: string
  valid: boolean
  trusted: boolean
  detail: string
  signerSha256?: string
}

export interface Violation {
  code: string
  field: string
  message: string
}

export interface FatalError {
  code: string
  field: string
  message: string
}

export type CheckKey =
  | 'signatureValid'
  | 'issuerTrusted'
  | 'digestMatch'
  | 'payloadTypeOk'
  | 'statementTypeOk'
  | 'predicateTypeOk'
  | 'buildTypeOk'
  | 'sourceHostAllowed'
  | 'sourcePinned'
  | 'policyAllow'

export interface VerificationRecord {
  id: string
  createdAt: string
  artifactName: string
  artifactSize: number
  artifactSha256: string
  envelopeRaw: unknown
  statement: Record<string, unknown> | null
  payloadType: string
  signatures: SigResult[] | null
  builderId: string
  buildType: string
  sourceUri: string
  sourceCommit: string
  subjectDigest: string
  checks: Record<CheckKey, boolean> | null
  violations: Violation[] | null
  allow: boolean
  fatal?: FatalError
}

export interface DemoScenario {
  id: string
  title: string
  description: string
  artifactFile: string
  expectedAllow: boolean
  expectedChecks: string[]
}

export interface ListResponse {
  items: VerificationRecord[]
  total: number
}

export interface HealthResponse {
  status: string
  store: string
}

export interface TrustRoot {
  version: number
  keys: { keyId: string; builderId: string }[]
  allowedSourceHosts: string[]
  allowedBuildTypes: string[]
}
