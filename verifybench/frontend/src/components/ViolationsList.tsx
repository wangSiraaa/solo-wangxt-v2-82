import type { VerificationRecord } from '../types'

/** 把失败原因定位到具体证据字段的列表。 */
export default function ViolationsList({ record }: { record: VerificationRecord }) {
  if (record.fatal) {
    return (
      <div className="error-box">
        <div>
          <strong>{record.fatal.code}</strong>
          {'　'}
          <span className="field-path">{record.fatal.field}</span>
        </div>
        <div className="mt8">{record.fatal.message}</div>
      </div>
    )
  }
  if (!record.violations || record.violations.length === 0) {
    return <div className="muted small">策略未触发任何拒绝项。</div>
  }
  return (
    <div>
      {record.violations.map((v, i) => (
        <div className="error-box" key={i}>
          <div>
            <strong>{v.code}</strong>
            {'　'}
            <span className="field-path">{v.field}</span>
          </div>
          <div className="mt8">{v.message}</div>
        </div>
      ))}
    </div>
  )
}
