# dq 7187 Requester + n6 720202 Worker 身份准备（Verifier 暂缓）

当前阶段只准备两个已经有公开控制权来源的角色：

- Requester：`dq` / `7187.bitmap` / `bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq`，来源：`existing public 7187 claim`。
- Worker：`n6` / `720202.bitmap` / `bc1qe45ynsz8tkky0nmxfuvjga7z0lwkalfkxkdln6`，来源：`existing public 720202 claim`。
- Verifier：`pending-registration`。本阶段不填写、不消费、不声明任何 Verifier 地址。

`claims_scope` 固定为：`independent_controller=false`、`external_adoption=false`、`real_payment=false`。准备结果不代表 pilot 可执行、已结算或已经进入生产。

## 生成准备材料

```bash
organa-cell-kit pilot-identity-prepare /path/to/dq-n6-pilot \
  --config config/pilot-identity-production.json
```

命令只为 Requester 和 Worker 生成：

- `identity/<role>/identity-document.json`
- `identity/<role>/signature-request.json`
- `identity/identity-preparation.json`
- `identity/verifier-pending-worksheet.json`

不会生成 Ed25519 密钥，不会生成 BIP-322 签名，不会调用钱包或 computer-use，不会创建交易或 PSBT。

## 安全的下一步

1. `dq` 人工使用控制 `7187.bitmap` 的对应钱包，仅签署 `identity/requester/signature-request.json` 中完整、原样的 UTF-8 `message`。
2. `n6` 人工使用控制 `720202.bitmap` 的对应钱包，仅签署 `identity/worker/signature-request.json` 中完整、原样的 UTF-8 `message`。
3. 两次操作都只能使用 BIP-322 Simple Message Signing。不得提供种子、助记词、私钥、钱包密码；不得发起交易、转账或 PSBT。
4. Verifier 继续暂停，直到完成独立的人工注册和审查。即使 Requester/Worker 已签名，也不得宣称 pilot 已执行或已结算。
