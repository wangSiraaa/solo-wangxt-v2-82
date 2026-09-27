# 软件供应链核验工作台

下载构建产物前,验证它确实来自**允许的源码与构建流程**。
全栈实现:React + TypeScript 前端、Go 核验后端、OPA 信任策略、PostgreSQL 持久化。

## 核验流水线

```
本地产物 ──┐
          ├─> Go 后端
DSSE 证据 ─┘   1. 解析 DSSE 信封(payloadType / payload / signatures)
               2. Ed25519 验签(crypto/ed25519,PAE 预认证编码)
               3. 解析 in-toto Statement + SLSA Provenance 谓词
               4. 计算产物 SHA-256,与声明 subject 摘要比对
               5. OPA(rego)执行信任策略,输出逐字段 violation
               6. PostgreSQL 保存产物摘要、证据与判定结果
```

**安全约束:产物字节只参与 SHA-256 计算,任何失败路径都不会执行、解压或解释产物内容。**

## 四个判定面板

判定详情页分别展示,失败原因定位到具体证据字段(JSON 路径):

| 面板 | 内容 | 失败字段示例 |
|---|---|---|
| 签名有效性 | DSSE 信封每条签名的 Ed25519 验签结果 | `signatures[0].sig` |
| 签发者信任 | keyid 是否在受信签名者列表 | `signatures[0].keyid` |
| 摘要一致性 | 声明摘要 vs 本地产物实际摘要 | `subject[0].digest.sha256` |
| 策略结论 | OPA 汇总的 allow/deny 与全部违反项 | `predicate.runDetails.builder.id` 等 |

## 三组固定演示数据

`fixtures/` 下由 `make fixtures` 生成,便于逐项录制核验结果:

| 用例 | 场景 | 预期 |
|---|---|---|
| `valid` | 受信构建者签名,摘要一致 | **allow** |
| `tampered` | 证据合法但本地产物被篡改,摘要不一致 | **deny** |
| `untrusted-builder` | 签名有效但签发者与构建流程均不受信 | **deny** |

## 快速开始

```bash
# 1. 启动 PostgreSQL(任选其一)
docker compose up -d db          # 或任何本地 postgres:16

# 2. 生成演示数据 + 启动后端(自动建库建表,监听 :8080)
make run

# 3. 前端(二选一)
make build-web                   # 构建后由 :8080 直接托管
make dev-web                     # 或 Vite 开发服务器 :5173(代理 /api)

# 4. 命令行快速验证三组用例
make demo-check
```

环境变量:`ADDR`(默认 `:8080`)、`DATABASE_URL`、`ADMIN_DATABASE_URL`、`APP_ROOT`。

## 信任策略

- `policy/trust.rego` — OPA 策略:签名必须有效、签发者必须受信、
  摘要必须一致、构建者与谓词类型必须在允许列表。
- `policy/trusted.json` — 安全团队维护的数据:受信签名者、允许的构建者与谓词类型。
- `fixtures/keys/keyring.json` — 服务端已知公钥环(含可信与不可信密钥,
  用于把"签名有效"与"签发者受信"拆成两个独立判定)。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/verify` | multipart 上传 `artifact` + `envelope`,执行核验 |
| GET  | `/api/verifications` | 历史记录 |
| GET  | `/api/verifications/{id}` | 判定详情(含四个面板数据) |
| GET  | `/api/demos` | 演示用例列表 |
| POST | `/api/demos/{name}/verify` | 用固定演示数据执行核验 |

## 目录结构

```
├── policy/            OPA 信任策略与数据
├── fixtures/          三组固定演示数据(生成)
├── server/
│   ├── cmd/server/        HTTP 服务入口
│   ├── cmd/genfixtures/   演示数据生成器
│   └── internal/
│       ├── dsse/          DSSE 封装解析与 PAE 验签
│       ├── intoto/        in-toto Statement / SLSA Provenance 解析
│       ├── verify/        核验流水线 + OPA 求值器
│       ├── store/         PostgreSQL 持久化
│       └── api/           HTTP API
└── web/               React + TypeScript 前端(上传 / 历史 / 判定详情)
```
