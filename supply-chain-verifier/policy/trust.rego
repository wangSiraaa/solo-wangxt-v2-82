# 软件供应链信任策略
#
# 输入(input)由 Go 核验流水线在密码学校验之后构造:
#   signature_valid  bool   DSSE 信封上全部签名是否通过 Ed25519 验签
#   signer_keyid     string 签名者密钥 ID
#   builder_id       string in-toto 声明中的构建者身份
#   digest_match     bool   声明摘要与本地产物实际摘要是否一致
#   statement_type   string  in-toto Statement 类型
#   predicate_type   string 谓词类型(须为 SLSA Provenance)
#
# 数据(data)来自 policy/trusted.json,由安全团队维护:
#   trusted_signers        可信签名者 keyid 集合
#   allowed_builders       允许的构建者身份列表
#   allowed_predicate_types 允许的谓词类型列表
#
# 输出: decision = {"allow": bool, "violations": [{"field","message"}]}
# 每条 violation 的 field 指向证据中的具体字段,供前端定位失败原因。

package supplychain

import rego.v1

default decision := {"allow": false, "violations": [{"field": "_", "message": "策略未产生有效判定"}]}

decision := {"allow": true, "violations": []} if {
	count(violations) == 0
}

decision := {"allow": false, "violations": sorted} if {
	count(violations) > 0
	sorted := sort(violations)
}

# --- 逐项检查,失败即产生定位到字段的 violation ---

violations contains v if {
	not input.signature_valid
	v := {"field": "signatures[0].sig", "message": "DSSE 签名未通过 Ed25519 验签"}
}

violations contains v if {
	not data.trusted_signers[input.signer_keyid]
	v := {"field": "signatures[0].keyid", "message": sprintf("签发者 keyid=%q 不在受信签名者列表中", [input.signer_keyid])}
}

violations contains v if {
	not input.digest_match
	v := {"field": "subject[0].digest.sha256", "message": "声明中的产物摘要与本地产物实际摘要不一致"}
}

violations contains v if {
	not input.builder_id in data.allowed_builders
	v := {"field": "predicate.runDetails.builder.id", "message": sprintf("构建者 %q 不在允许的构建流程列表中", [input.builder_id])}
}

violations contains v if {
	input.statement_type != "https://in-toto.io/Statement/v1"
	v := {"field": "_type", "message": sprintf("声明类型 %q 不是受支持的 in-toto Statement v1", [input.statement_type])}
}

violations contains v if {
	not input.predicate_type in data.allowed_predicate_types
	v := {"field": "predicateType", "message": sprintf("谓词类型 %q 不在允许列表中", [input.predicate_type])}
}
