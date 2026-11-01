# sfi-adblock

**sing-box for iOS 的「按需 MITM 去广告」改造**：只对命中规则集的域名解密 TLS，默认关闭，失败回退直通；兼容小火箭（Shadowrocket）`.sgmodule` 模块。

> **M1 已废弃**：M1 只是 `DomainSuffix` + `reject` 的域名拦截，挡不住同域广告、路径级广告和 CNAME 伪装。M1 代码保留在 `m1-domain-block` 分支，`main` 已转向 M2（MITM）。

## 当前进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| M2.1 | CA（ECDSA P-256，私钥 Keychain）、按需 MITM、HTTP/1.1 解密与 URL Rewrite、失败回退、计数、设置页基础 UI | 已完成 |
| M2.2 | 可视化：模块导入（文件/URL）、模块启用禁用、规则列表（可搜索）、CA 导出（.mobileconfig） | 已完成 |
| M2.3 | `.sgmodule` 兼容：`[MITM]` `[URL Rewrite]` `[Rule]`、`[Script]`/不支持段跳过提示 | 已完成 |

构建产物：GitHub Actions 每次 push 出的**未签名 IPA**（artifact `sfi-adblock-unsigned-ipa`）。

## 它怎么工作

- **按需解密**：只有「MITM 总开关 on + CA 已生成且被系统信任 + 连接 SNI 命中模块 `[MITM]` host 列表」才终止 TLS；其余连接完全直通（不读明文、不建上游 TLS）。
- **CA 信任门控**：隧道进程用 `SecTrustEvaluateWithError` 检查 CA 是否已安装并「完全信任」。未信任时**不启用解密**（网络完全正常），只保留 `[Rule]` 拦截；UI 显示 `CA not trusted` 并给出安装步骤。若设备/签名方式导致信任检查不可用，可手动打开 **Force Decrypt** 覆盖。
- **CA**：ECDSA P-256、10 年；私钥优先存 **iOS Keychain**（`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`）；未签名/重签名环境缺少 keychain entitlement（`-34018`）时自动降级为 App Group 内 `0600` 文件，保证功能可用（README 的「已知限制」有说明）。证书以 PEM 存在 App Group，供 App 展示指纹/导出。
- **leaf**：按域名现签 ECDSA P-256，7 天有效，内存 LRU 缓存 256 条。
- **协议最小集**：只协商 `http/1.1`（避免 h2/HPACK）；支持 `reject` / `reject-200` / `reject-img` / `reject-dict` / `reject-array` / `302` / `307`。
- **上游**：通过 sing-box 已选中的 outbound 拨号，再用 Mozilla 根证书校验（iOS 上 Go 读不到系统信任库）；keep-alive 复用一条上游 TLS。
- **失败回退**：握手前任何不满足（端口/规则/配额/内存水位）→ 直通；低内存（>36 MiB 堆）时暂停解密；客户端握手失败（pinning/mTLS）→ 关闭并 10 分钟内旁路该域；HTTP 解析失败 → 解密字节盲转发。
- **计数**：`intercepted / rewritten / blocked / fallbacks / activeConnections`，设置页实时显示。

## 改动文件（overlay，CI 覆盖到上游 clone）

上游固定到：

| 仓库 | commit |
|---|---|
| `SagerNet/sing-box` | `e5d91fa79f6319d5de940d6c81d81f0fe53b9476` |
| `SagerNet/sing-box-for-apple` | `0d1b59fc5e58c8e6b2239e576e4fd979c502a8fb` |

新增/修改：

| 文件 | 作用 |
|---|---|
| `common/mitm/*.go`（新增，~1,700 行，含本地测试） | 状态/CA（Keychain cgo）/host 匹配/`.sgmodule` 解析/H1 引擎/回退/计数 |
| `common/certificate/mitm_pool.go`（新增） | 暴露内嵌 Mozilla 根证书池 |
| `route/route.go` | +10 行 hook：`mitm.TryIntercept` |
| `daemon/instance.go` | +2 行：服务启动/reload 时 `mitm.Prepare()` |
| `experimental/libbox/mitm.go`（新增） | gomobile 导出：开关、路径、CA 管理、模块导入/列表、统计 |
| `Library/Network/ExtensionProvider.swift` | 启动/重载时把开关与路径传给 Go |
| `Library/Network/ExtensionProfile.swift` | 把开关与 CA/模块目录写进 start options |
| `Library/Database/SharedPreferences.swift` | `mitm_enabled` 偏好（默认 false） |
| `ApplicationLibrary/Views/Setting/CoreView.swift` | 设置页 MITM 区块（开关/CA/状态计数） |

## 使用

1. App → 设置 → **Core**；
2. 点 **Generate / Rotate CA**（自动重启 VPN 生成 CA）；
3. 用 **Export CA (.mobileconfig)** 或 **Copy CA Certificate** 导出证书，安装描述文件，并在 **设置 → 通用 → 关于 → 证书信任设置** 里开启完全信任；
4. 在 **MITM Modules** 里 **Import .sgmodule**（文件选择器）或 **Import from URL**；
5. 打开 **MITM Ad Block** 总开关并重启 VPN；
6. 回来可以看到 Status / Intercepted / Rewrites / Rule Blocks / Fallbacks 计数；**View MITM Rules** 可搜索当前生效的 host 与 rewrite 规则。

## 构建

与 M1 相同的 workflow：`.github/workflows/build-ipa.yml`，`macos-26`，从零 checkout 上游 → 覆盖 overlay → `go test ./common/mitm` → 构建 `Libbox.xcframework` → `xcodebuild`（关闭签名）→ 打包 IPA → artifact。

```bash
gh run watch -R lipeiying032/sfi-adblock
gh run download -R lipeiying032/sfi-adblock -n sfi-adblock-unsigned-ipa -D artifacts
```

## `.sgmodule` 兼容（M2.3 目标）

| 段 | 支持 |
|---|---|
| `[MITM]` | `hostname = %APPEND% ...` 与 `%INSERT%`；`*.a.com`、`*api.x.com`、`103.41.167.*` 等通配；`1.2.3.4:2515` 去端口；`-host` 排除；`{{{...}}}` 未填参数跳过 |
| `[URL Rewrite]` | `pattern replacement [reject|reject-200|reject-img|reject-dict|reject-array|302|307]`；兼容 `pattern - reject` 与 `pattern https://target 302` |
| `[Rule]` | `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` + `REJECT` |
| `[Script]` | **跳过**，导入结果提示忽略条数 |
| `[Map Local]` / `[Body Rewrite]` | 暂不支持，导入时提示忽略 |

## 已知限制

- 未签名 IPA，需要自签；Network Extension 还需要 `packet-tunnel-provider` entitlement 与 App Group（上游 App 本身就依赖 App Group）；
- CI 用 Xcode 26 构建，产物最低 iOS 16.0（上游默认 15.0，Xcode 26 的 SwiftUI `buildIf` 可用性检查要求 16.0，workflow 里用 `IPHONEOS_DEPLOYMENT_TARGET=16.0` 覆盖）；
- CA 由隧道进程生成（Keychain 默认访问组），因此生成/删除 CA 需要隧道处于连接状态；未连接时操作会排队，下次启动生效；
- 未签名构建通常没有 keychain entitlement，此时 CA 私钥降级存 App Group 文件（`0600`）。要严格只用 Keychain，需要自签时带上 keychain access group；
- CA 信任检查依赖系统 trust store；若检查结果不可用（`Force Decrypt` 可覆盖），解密不会启动；
- 只做 HTTP/1.1，不做 h2/QUIC/WebSocket 改写；
- pinning/mTLS 客户端会握手失败，首次失败后自动旁路该域 10 分钟；
- 规则匹配依赖 SNI，ECH 无法拦截；
- `[Script]` / `[Map Local]` / `[Body Rewrite]` 不执行，导入时统计并提示。

## License

GPL-3.0-or-later。上游 sing-box / sing-box-for-apple 均为 GPL-3.0。详见 `LICENSE`。
