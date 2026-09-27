# 软件供应链核验工作台（VerifyBench）

在下载构建产物**之前**验证它来自**允许的源码**和**允许的构建流程**。
工作台对「本地产物 + DSSE 证据」执行完整的供应链核验流水线，并把每一步判定
（签名有效性、签发者信任状态、摘要一致性、策略结论）逐项展示，失败原因定位到
**具体证据字段**；核验失败时产物字节不会被保留、不可下载，全程**不执行产物内容**。

## 技术栈

| 层 | 技术 |
| --- | --- |
| 前端 | React 18 + TypeScript + Vite + react-router |
| 后端 | Go 1.22（标准库 `crypto/ed25519` 验签） |
| 证据格式 | DSSE v1.0 封装 + in-toto v1 声明（SLSA provenance v1 谓词） |
| 策略引擎 | Open Policy Agent（OPA Rego，Go 内嵌评估） |
| 数据库 | PostgreSQL（pgx 连接池）；未配置时回退到内存存储 |

## 核验流水线

```
上传产物字节 + DSSE envelope.json
        │  （字节只做哈希，绝不执行）
        ▼
1. 解析 DSSE 封装         payloadType / payload / signatures
2. Ed25519 验签           按 DSSE PAE 重组签名内容，crypto/ed25519 校验
3. 解析 in-toto 声明      _type / predicateType / subject / builder / buildType / 源码依赖
4. sha256 比对            实测产物摘要 vs subject[].digest.sha256
5. OPA 策略判定           deny 规则集合 → allow + 逐项 checks + 字段级 violations
6. 持久化（PostgreSQL）   证据、判定入库；仅 allow 的记录保存产物字节
```

策略输入由后端构造，客户端无法影响信任判定。

## 内置三组固定演示数据

密钥由固定种子确定性派生（`cmd/gendemo`），三组场景可逐项录制核验结果：

| 场景 | 构造 | 预期结果 |
| --- | --- | --- |
| **正常产物** `normal` | 受信构建者签名，摘要一致，源码宿主/构建类型合规 | 全部通过，允许下载 |
| **被改过的文件** `tampered` | 签名仍然有效，产物在签名后被追加了投毒内容 | `digest_mismatch`，定位到 `subject[0].digest.sha256`，拒绝 |
| **不受信任构建者** `untrusted` | 证据自洽，但签名密钥与 `builder.id` 不在信任根 | `signature_not_trusted` + `builder_untrusted`，定位到 `predicate.runDetails.builder.id`，拒绝 |

另外手工验证过：篡改已签名 payload → 签名本身失效（`signature_not_trusted`）；
上传畸形证据 → 返回 `envelope_parse_error` 致命错误而非崩溃。

## 安全边界：失败路径不执行产物内容

- 产物字节在服务端仅进入 `crypto/sha256`，不写入临时可执行路径、不交给任何解释器。
- 策略拒绝的记录：
  - 不写入 `verification_artifacts` 表（PostgreSQL 后端）或内存映射；
  - `GET /api/verifications/{id}/artifact` 直接返回 **403**。
- 有单元测试锁定该边界：`internal/api/api_test.go`（拒绝内容不会出现在 403 响应中）。

## 快速开始

### 方式 A：Docker Compose（PostgreSQL + API + 前端）

```bash
docker compose up --build
# 打开 http://localhost:8080
```

### 方式 B：本地开发

需要 Go 1.22+、Node 20+，以及一个 PostgreSQL（可选）。

```bash
# 1. 前端
cd frontend
npm install
npm run build        # 或 npm run dev 走 Vite 代理到 :8080

# 2. 后端
cd ../backend
go test ./...        # 全部单测
go run ./cmd/server  # 默认 :8080，无 DATABASE_URL 时用内存存储
```

使用 PostgreSQL：

```bash
export DATABASE_URL='postgres://user:pass@localhost:5432/verifybench?sslmode=disable'
go run ./cmd/server
```

其他环境变量：`ADDR`（监听地址）、`TRUST_ROOT`（信任根 JSON 路径，缺省用内置演示信任根）、
`FRONTEND_DIST`（前端构建目录）。

表结构由后端启动时自动创建（`verifications` 与 `verification_artifacts`）。

### 重新生成演示数据

```bash
cd backend && go run ./cmd/gendemo ./internal/demo/demodata
```

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查与当前存储类型 |
| GET | `/api/demo` | 三组演示场景元数据 |
| GET | `/api/demo/{id}/artifact` / `/envelope` | 下载演示样本 |
| POST | `/api/verify/demo/{id}` | 对内置场景执行核验 |
| POST | `/api/verify` | multipart 上传 `artifact` + `envelope` |
| GET | `/api/verifications` | 历史记录列表（倒序） |
| GET | `/api/verifications/{id}` | 判定详情（证据、checks、字段级违规） |
| GET | `/api/verifications/{id}/artifact` | 下载产物（仅通过核验，否则 403） |
| GET | `/api/policy` / `/api/trust-root` | 查看 Rego 策略与信任根 |

判定记录的 `violations[]` 每项形如：

```json
{ "code": "digest_mismatch",
  "field": "subject[0].digest.sha256",
  "message": "uploaded artifact sha256 74ef... does not match attested subject digest 8d6c..." }
```

前端详情页据此高亮证据 JSON 中的对应字段并列出字段当前值。

## 信任策略（OPA Rego 要点）

策略文件：`backend/internal/policy/supplychain.rego`（编译进二进制，`/api/policy` 可查看）。
拒绝规则包括：

- `payload_type_unsupported` / `statement_type_unsupported` / `predicate_type_unsupported`
- `signature_not_trusted`：没有任何签名既密码学有效、又来自信任根密钥
- `builder_untrusted` → `predicate.runDetails.builder.id`：builder 未注册，或未用其登记密钥签名
- `digest_mismatch` → `subject[i].digest.sha256`
- `build_type_not_allowed`、`source_dependency_missing`、`source_host_not_allowed`、
  `source_commit_unpinned`（源码必须 pin 到 `@<commit>` 或带 gitCommit/sha256 digest）

信任根格式见 `backend/internal/demo/demodata/trust-root.json`：受信 Ed25519 公钥
（keyId = `sha256:` 前缀 + 公钥原始字节摘要）到 builderId 的映射、允许的源码宿主与构建类型。

## 目录结构

```
backend/
  cmd/server/         HTTP 服务入口
  cmd/gendemo/        确定性生成三组演示数据
  internal/dsse/      DSSE 封装解析 + PAE + Ed25519 验签
  internal/intoto/    in-toto v1 / SLSA provenance v1 解析
  internal/trust/     信任根加载与校验
  internal/policy/    OPA Rego 策略（.rego 编译期内嵌）
  internal/verify/    核验流水线编排
  internal/store/     PostgreSQL 与内存存储实现
  internal/api/       HTTP 层（含失败即 403 的产物下载）
  internal/demo/      内嵌演示数据（go:embed）
frontend/src/
  pages/              首页演示 / 上传核验 / 历史记录 / 判定详情 / 策略与信任根
  components/         四项核验面板、字段级违规列表、判定横幅
```
