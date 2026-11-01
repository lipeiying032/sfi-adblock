# sfi-adblock

**sing-box for iOS 的去广告改造（M2：可视化 MITM 去广告）**。

> **M1 已废弃**：M1 只是 `DomainSuffix` + `reject` 的域名拦截，挡不住同域广告、路径级广告和 CNAME 伪装。M1 代码保留在 `m1-domain-block` 分支，`main` 已回退并转向 M2。

本仓库只存放改动（`overlay/`）、构建脚本和 GitHub Actions；上游源码在 CI 里按固定 commit 拉取，从零可复现出**未签名 IPA**。

[![Build unsigned IPA](https://github.com/lipeiying032/sfi-adblock/actions/workflows/build-ipa.yml/badge.svg)](https://github.com/lipeiying032/sfi-adblock/actions/workflows/build-ipa.yml)

---

## 1. 这是什么 / 不是什么

| 是 | 不是 |
|---|---|
| 一个可编译、可出 IPA 的 sing-box for iOS 衍生构建 | 不是 sing-box 官方版本 |
| M1：内置域名规则 + `reject`（DNS/连接层） | 不做 TLS MITM、不装 CA、不做 HTTP 改写 |
| 一个设置页开关（Settings → Core → Ad Block） | 不做规则订阅、不做脚本、不做 per-app 配置 |

设计取舍见 `/root/sfi-mitm/report.md`（按需 MITM 报告）：**M1 先用零成本的域名级拦截拿到大部分收益**，MITM 留到 M2，且默认关闭。

## 2. 改了什么（全部是 overlay，不 vendor 上游）

上游固定版本（CI 精确 checkout 这两个 commit）：

| 仓库 | commit |
|---|---|
| [SagerNet/sing-box](https://github.com/SagerNet/sing-box) | `e5d91fa79f6319d5de940d6c81d81f0fe53b9476` |
| [SagerNet/sing-box-for-apple](https://github.com/SagerNet/sing-box-for-apple) | `0d1b59fc5e58c8e6b2239e576e4fd979c502a8fb` |
| `Frameworks/Runestone` 子模块 | `baeb3cbf8332d26b4f7b4c175a01f288ebbf3e7f`（CI 自动初始化） |

改动文件（`overlay/` 里是**完整文件**，CI 直接覆盖到上游 clone 上）：

| # | 文件 | 改动 |
|---|---|---|
| 1 | `sing-box/common/adblock/adblock.go`（新增） | 嵌入域名清单；`SetEnabled()`；`Inject()` 在配置最前面插入两条 route rule：`{"action":"sniff"}` + `{"domain_suffix":[...],"action":"reject"}` |
| 2 | `sing-box/common/adblock/adblock_domains.txt`（新增） | 12,598 条广告/追踪域名后缀（生成方式见 §6） |
| 3 | `sing-box/daemon/instance.go` | +2 行：`import common/adblock`；`options = adblock.Inject(options)`（服务启动/reload 时生效） |
| 4 | `sing-box/experimental/libbox/adblock.go`（新增） | gomobile 导出 `SetAdBlockEnabled(bool)` |
| 5 | `sing-box-for-apple/Library/Network/ExtensionProvider.swift` | +2 行：启动/收到配置消息时调用 `LibboxSetAdBlockEnabled(...)` |
| 6 | `sing-box-for-apple/Library/Network/ExtensionProfile.swift` | +1 行：把偏好写进 tunnel start options |
| 7 | `sing-box-for-apple/Library/Database/SharedPreferences.swift` | +1 行：`ad_block_enabled` 偏好 |
| 8 | `sing-box-for-apple/ApplicationLibrary/Views/Setting/CoreView.swift` | 设置页新增 “Ad Block” 开关（读取/写入偏好） |

**为什么必须改这些地方**：

- 拦截规则必须在 **config 解析之后、box.New 之前**注入（`daemon/instance.go:newInstance`），这样规则引擎、outbound、DNS 全部复用，零新引擎；
- 域名条件要生效，必须先 `sniff` 出 SNI/Host/DNS question，否则 tun 拿到的是 IP。所以第一条注入的规则是 `action: sniff`，第二条才是 `reject`；
- 开关状态从 App 传到 Extension 进程，只能走 start options + gomobile 导出函数（`LibboxSetAdBlockEnabled`），所以 Swift 侧共 4 处小改。

不引入任何新 Go module / Swift Package；清单以 `go:embed` 编进 Libbox，仓库里不提交任何二进制。

## 3. 使用

1. 用你自己的证书/描述文件对 IPA 重签并安装（见 §5 的限制）；
2. 打开 App → 设置 → **Core** → 打开 **Ad Block**；
3. 重启 VPN（断开再连接）——开关在 tunnel 启动时读取；
4. 访问已知广告域名应被直接拒绝（连接被 reset，DNS 查询也会被拒绝）。

关闭开关并重启 VPN 即恢复原行为；App 不写入、不修改你的 profile 配置。

## 4. 构建（GitHub Actions，可复现）

Workflow：`.github/workflows/build-ipa.yml`

- Runner：`macos-26`（Xcode 26.6；上游项目用了 iOS 26 SDK 的 API，Xcode 16 编译不过）
- 步骤：checkout 本仓库 → 按 SHA checkout 两个上游 → 覆盖 overlay → 给 Go 打 iOS CPU 特性补丁 → 安装 gomobile → 构建 `Libbox.xcframework`（`ios/arm64`）→ `xcodebuild -scheme SFI`（关闭签名）→ 打包 `Payload/SFI.app` → 上传 artifact
- 触发：push 到 `main`，或手动 `workflow_dispatch`

产物：`sfi-adblock-unsigned-ipa`（artifact），内部文件名 `sfi-adblock-unsigned.ipa`。

本地（macOS + Xcode 26）复现：

```bash
git clone https://github.com/lipeiying032/sfi-adblock.git
cd sfi-adblock
git clone https://github.com/SagerNet/sing-box.git sing-box
git -C sing-box fetch --depth 1 origin e5d91fa79f6319d5de940d6c81d81f0fe53b9476
git -C sing-box checkout e5d91fa79f6319d5de940d6c81d81f0fe53b9476
git clone --recursive https://github.com/SagerNet/sing-box-for-apple.git
git -C sing-box-for-apple fetch --depth 1 origin 0d1b59fc5e58c8e6b2239e576e4fd979c502a8fb
git -C sing-box-for-apple checkout 0d1b59fc5e58c8e6b2239e576e4fd979c502a8fb
git -C sing-box-for-apple submodule update --init --recursive
cp -R overlay/sing-box/. sing-box/
cp -R overlay/sing-box-for-apple/. sing-box-for-apple/

cd sing-box
git tag -f v1.15.0-alpha.13
bash .github/patch_go_for_ios.sh
make lib_install
export PATH="$PATH:$(go env GOPATH)/bin"
go run ./cmd/internal/build_libbox -target apple -platform ios/arm64
cd ../sing-box-for-apple
xcodebuild build -project sing-box.xcodeproj -scheme SFI -configuration Release \
  -destination 'generic/platform=iOS' -derivedDataPath build/DerivedData \
  -skipPackagePluginValidation CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" BASE_PACKAGE_IDENTIFIER=io.nekohasekai.sfa \
  APP_GROUP_IDENTIFIER=group.io.nekohasekai.sfa
```

## 5. 产物与已知限制

- **未签名**：IPA 里没有签名，需要自签（AltStore/TrollStore/企业证书等）才能安装；
- 就算签了名，Network Extension 还需要 **`packet-tunnel-provider` entitlement + 匹配的 App Group**；用个人开发者证书重签时必须同步改 `BASE_PACKAGE_IDENTIFIER`/`APP_GROUP_IDENTIFIER` 和 entitlements，否则 VPN 起不来；
- 只做**域名级**拦截：不处理路径、不处理响应体，不做 MITM；
- 规则匹配依赖 sniff（TLS SNI / HTTP Host / QUIC / DNS question），ECH 或无 SNI 的连接挡不住；
- 开关只在 tunnel 启动时生效，改完要重启 VPN；
- 清单是编译期固定的快照，不会自动更新（更新方式见 §6）。

## 6. 内置清单的来源与再生成

清单来自 [AdGuard Filters](https://github.com/AdguardTeam/AdguardFilters)（GPL-3.0）的 ad server / tracking 段，取 `||domain^` 规则、去掉 IP 与允许列表、按后缀去重（父域已存在则删除子域），最后得到 12,598 条。

```bash
python3 scripts/update_adblock_list.py
# 输出 overlay/sing-box/common/adblock/adblock_domains.txt
```

清单是**提交进仓库的快照**，CI 不联网更新，保证同一 commit 构建结果稳定。

## 7. License

GPL-3.0-or-later。上游 sing-box / sing-box-for-apple 均为 GPL-3.0；内置域名清单来自 GPL-3.0 的 AdGuard Filters。详见 `LICENSE`。
