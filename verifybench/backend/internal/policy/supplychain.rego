package supplychain.verify

# Explicit trust policy for the supply-chain verification workbench.
#
# Input (constructed by the Go verifier, never by the client):
#   input.payloadType            envelope.payloadType
#   input.artifact               {"name": "...", "sha256": "<hex digest of uploaded bytes>"}
#   input.statement              the decoded in-toto statement (attestation content)
#   input.signatures[]           per-signature crypto results {keyId, valid, trusted}
#   input.trust.builders         map builderId -> {"keyId": "..."}  (from trust root)
#   input.trust.allowedSourceHosts[]
#   input.trust.allowedBuildTypes[]
#
# Every denial carries:
#   code    machine-readable failure code
#   field   concrete JSON path inside the evidence (envelope/statement) that caused it
#   message human-readable explanation
#
# `allow` is true only when there are zero denials.

import rego.v1

dsse_payload_type := "application/vnd.in-toto+json"
statement_type := "https://in-toto.io/Statement/v1"
predicate_type := "https://slsa.dev/provenance/v1"

# Signatures that are cryptographically valid AND produced by a trusted key.
valid_trusted_sigs contains sig if {
	sig := input.signatures[_]
	sig.valid == true
	sig.trusted == true
}

default has_valid_signature := false
has_valid_signature if count(valid_trusted_sigs) > 0

builder_id := input.statement.predicate.runDetails.builder.id

# Issuer is trusted when the statement names a registered builder AND the
# evidence is signed with exactly that builder's registered key.
default issuer_trusted := false
issuer_trusted if {
	input.trust.builders[builder_id]
	registered_key := input.trust.builders[builder_id].keyId
	some sig in valid_trusted_sigs
	sig.keyId == registered_key
}

# Locate subjects attesting to the uploaded artifact by name.
matched_subject contains {"index": i, "subject": s} if {
	s := input.statement.subject[i]
	s.name == input.artifact.name
}

default digest_match := false
digest_match if {
	some m in matched_subject
	m.subject.digest.sha256 == input.artifact.sha256
}

# Source dependency handling: require a pinned git dependency on an allowed host.
git_deps contains dep if {
	some i
	d := input.statement.predicate.buildDefinition.resolvedDependencies[i]
	startswith(d.uri, "git+")
	dep := {"index": i, "uri": d.uri, "digest": d.digest}
}

source_host contains host if {
	some d in git_deps
	stripped := substring(d.uri, 4, -1)
	after_scheme := split(stripped, "://")[1]
	host := split(after_scheme, "/")[0]
}

# A git dependency is pinned when the URI carries @<commit> or records a
# gitCommit/sha256 digest.
default pinned_dep := false
pinned_dep if {
	some d in git_deps
	contains(d.uri, "@")
}

pinned_dep if {
	some d in git_deps
	d.digest.gitCommit
}

pinned_dep if {
	some d in git_deps
	d.digest.sha256
}

default host_allowed := false
host_allowed if {
	some h in source_host
	h in input.trust.allowedSourceHosts
}

default build_type_ok := false
build_type_ok if input.statement.predicate.buildDefinition.buildType in input.trust.allowedBuildTypes

default payload_type_ok := false
payload_type_ok if input.payloadType == dsse_payload_type
default statement_type_ok := false
statement_type_ok if input.statement._type == statement_type
default predicate_type_ok := false
predicate_type_ok if input.statement.predicateType == predicate_type

deny contains {"code": "payload_type_unsupported", "field": "payloadType", "message": sprintf("envelope payloadType is %q, expected %q", [input.payloadType, dsse_payload_type])} if {
	not payload_type_ok
}

deny contains {"code": "statement_type_unsupported", "field": "_type", "message": sprintf("statement _type is %q, expected %q", [input.statement._type, statement_type])} if {
	not statement_type_ok
}

deny contains {"code": "predicate_type_unsupported", "field": "predicateType", "message": sprintf("predicateType is %q, expected %q", [input.statement.predicateType, predicate_type])} if {
	not predicate_type_ok
}

deny contains {"code": "signature_not_trusted", "field": "signatures", "message": "no signature is both cryptographically valid and produced by a key in the trust root"} if {
	not has_valid_signature
}

deny contains {"code": "builder_untrusted", "field": "predicate.runDetails.builder.id", "message": sprintf("builder %q is not registered in the trust root, or the evidence was not signed with its registered key", [builder_id])} if {
	not issuer_trusted
}

deny contains {"code": "subject_not_found", "field": "subject", "message": sprintf("statement contains no subject named %q", [input.artifact.name])} if {
	count(matched_subject) == 0
}

deny contains {"code": "digest_missing", "field": field, "message": "subject has no sha256 digest"} if {
	some m in matched_subject
	not m.subject.digest.sha256
	field := sprintf("subject[%d].digest.sha256", [m.index])
}

deny contains {"code": "digest_mismatch", "field": field, "message": message} if {
	some m in matched_subject
	d := m.subject.digest.sha256
	d != input.artifact.sha256
	field := sprintf("subject[%d].digest.sha256", [m.index])
	message := sprintf("uploaded artifact sha256 %s does not match attested subject digest %s", [input.artifact.sha256, d])
}

deny contains {"code": "build_type_not_allowed", "field": "predicate.buildDefinition.buildType", "message": sprintf("buildType %q is not in the allowed list", [input.statement.predicate.buildDefinition.buildType])} if {
	not build_type_ok
}

deny contains {"code": "source_dependency_missing", "field": "predicate.buildDefinition.resolvedDependencies", "message": "buildDefinition lists no git source dependency"} if {
	count(git_deps) == 0
}

deny contains {"code": "source_host_not_allowed", "field": field, "message": sprintf("source host is not in allowed list %v", [input.trust.allowedSourceHosts])} if {
	count(git_deps) > 0
	not host_allowed
	some d in git_deps
	field := sprintf("predicate.buildDefinition.resolvedDependencies[%d].uri", [d.index])
}

deny contains {"code": "source_commit_unpinned", "field": field, "message": "git source dependency is not pinned to a commit (@<sha> or gitCommit digest)"} if {
	count(git_deps) > 0
	not pinned_dep
	some d in git_deps
	field := sprintf("predicate.buildDefinition.resolvedDependencies[%d].uri", [d.index])
}

checks := {
	"signatureValid": has_valid_signature,
	"issuerTrusted": issuer_trusted,
	"digestMatch": digest_match,
	"payloadTypeOk": payload_type_ok,
	"statementTypeOk": statement_type_ok,
	"predicateTypeOk": predicate_type_ok,
	"buildTypeOk": build_type_ok,
	"sourceHostAllowed": host_allowed,
	"sourcePinned": pinned_dep,
	"policyAllow": count(deny) == 0,
}

result := {
	"allow": count(deny) == 0,
	"violations": [v | some v in deny],
	"checks": checks,
}
