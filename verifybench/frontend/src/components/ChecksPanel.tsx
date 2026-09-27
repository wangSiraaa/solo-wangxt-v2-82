import type { CheckKey, VerificationRecord } from '../types'

const CHECK_META: { key: CheckKey; label: string; desc: string }[] = [
  { key: 'signatureValid', label: '签名有效性', desc: 'DSSE 签名经 Ed25519（crypto/ed25519）按 PAE 编码验证，且密钥在信任根中' },
  { key: 'issuerTrusted', label: '签发者信任状态', desc: '证据中的 builder.id 已注册，且使用该构建者登记的密钥签名' },
  { key: 'digestMatch', label: '摘要一致性', desc: '上传字节的 sha256 与 in-toto subject[].digest.sha256 完全一致' },
  { key: 'policyAllow', label: '策略结论', desc: 'OPA Rego 策略的全部 deny 规则均未触发，允许下载产物' },
]

const EXTENDED_META: { key: CheckKey; label: string }[] = [
  { key: 'payloadTypeOk', label: 'DSSE payloadType' },
  { key: 'statementTypeOk', label: 'in-toto _type' },
  { key: 'predicateTypeOk', label: '谓词类型 SLSA provenance v1' },
  { key: 'buildTypeOk', label: '允许的 buildType' },
  { key: 'sourceHostAllowed', label: '源码宿主在允许列表' },
  { key: 'sourcePinned', label: '源码固定到提交（@sha / digest）' },
]

function Dot({ state }: { state: boolean | undefined }) {
  const cls = state === undefined ? 'na' : state ? 'ok' : 'bad'
  return <span className={`dot ${cls}`} />
}

export function CheckState({ state }: { state: boolean | undefined }) {
  if (state === undefined) return <span className="badge neutral">未评估</span>
  return state ? <span className="badge ok">通过</span> : <span className="badge bad">失败</span>
}

export default function ChecksPanel({
  record,
  extended = false,
}: {
  record: VerificationRecord
  extended?: boolean
}) {
  const checks = record.checks ?? ({} as Record<CheckKey, boolean>)
  return (
    <div>
      {CHECK_META.map(({ key, label, desc }) => (
        <div className="check-row" key={key}>
          <Dot state={checks[key]} />
          <div className="grow">
            <div className="check-label">{label}</div>
            <div className="check-desc">{desc}</div>
          </div>
          <CheckState state={checks[key]} />
        </div>
      ))}
      {extended && (
        <>
          <div className="section-title">扩展策略项</div>
          {EXTENDED_META.map(({ key, label }) => (
            <div className="check-row" key={key}>
              <Dot state={checks[key]} />
              <div className="grow">
                <div className="check-label">{label}</div>
              </div>
              <CheckState state={checks[key]} />
            </div>
          ))}
        </>
      )}
    </div>
  )
}
