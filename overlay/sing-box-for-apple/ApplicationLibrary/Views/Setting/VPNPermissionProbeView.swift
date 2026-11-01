#if !os(tvOS)
import Darwin
import Foundation
import NetworkExtension
import SwiftUI

#if os(iOS)
    import UIKit
#elseif os(macOS)
    import AppKit
#endif

// MARK: - Entitlement keys

/// Entitlements worth inspecting on a sideloaded build. The first two are the
/// ones this diagnostic page exists for.
private let vpnProbeEntitlementKeys: [String] = [
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.networking.vpn.api",
    "application-identifier",
    "com.apple.application-identifier",
    "com.apple.developer.team-identifier",
    "keychain-access-groups",
    "com.apple.security.application-groups",
    "get-task-allow",
    "aps-environment",
    "com.apple.developer.networking.multicast",
    "com.apple.developer.networking.wifi-info",
    "com.apple.developer.networking.HotspotConfiguration",
    "com.apple.developer.networking.multipath",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.icloud-services",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.developer.icloud-container-environment",
    "com.apple.developer.default-data-protection",
    "com.apple.developer.kernel.increased-memory-limit",
    "com.apple.developer.associated-domains",
    "com.apple.developer.siri",
    "com.apple.developer.healthkit",
    "com.apple.developer.homekit",
    "com.apple.developer.in-app-payments",
    "com.apple.developer.pass-type-identifiers",
    "com.apple.developer.usernotifications.communication",
]

// MARK: - Value rendering

private func vpnProbeCompactDescription(_ value: Any) -> String {
    if let string = value as? String {
        return "\"\(string)\""
    }
    if let number = value as? NSNumber {
        return number.stringValue
    }
    if let array = value as? [Any] {
        return "[" + array.map(vpnProbeCompactDescription).joined(separator: ", ") + "]"
    }
    if let dictionary = value as? [String: Any] {
        let body = dictionary.keys.sorted().map { key -> String in
            let rendered = dictionary[key].map(vpnProbeCompactDescription) ?? "nil"
            return "\(key): \(rendered)"
        }
        return "{" + body.joined(separator: ", ") + "}"
    }
    if let data = value as? Data {
        return "Data(\(data.count) bytes)"
    }
    return String(describing: value)
}

private func vpnProbePlistText(_ value: Any) -> String {
    guard PropertyListSerialization.propertyList(value, isValidFor: .xml),
          let data = try? PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0),
          let text = String(data: data, encoding: .utf8)
    else {
        return String(describing: value)
    }
    return text.trimmingCharacters(in: .whitespacesAndNewlines)
}

private func vpnProbeKeyStatus(key: String, in dictionary: [String: Any]?) -> String {
    guard let dictionary else {
        return "无法读取"
    }
    guard let value = dictionary[key] else {
        return "ABSENT（签名中不存在）"
    }
    return "PRESENT: \(vpnProbeCompactDescription(value))"
}

// MARK: - SecTask (dyld lookup)

/// iOS SDK does not declare SecTask, but the Security framework exports the
/// functions at runtime. Resolve them with dlsym so this page also compiles.
private enum SecTaskEntitlements {
    typealias CreateFunction = @convention(c) (CFAllocator?) -> Unmanaged<AnyObject>?
    typealias CopyValueFunction = @convention(c) (AnyObject, CFString, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFTypeRef>?

    struct Snapshot {
        var apiAvailable: Bool
        var apiError: String?
        var values: [String: Any]
        var missingKeys: [String]
        var keyErrors: [String]
    }

    static func read(keys: [String]) -> Snapshot {
        let library = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW)
        let defaultHandle = UnsafeMutableRawPointer(bitPattern: -2)

        func lookup(_ name: String) -> UnsafeMutableRawPointer? {
            if let library, let symbol = dlsym(library, name) {
                return symbol
            }
            return dlsym(defaultHandle, name)
        }

        guard let createSymbol = lookup("SecTaskCreateFromSelf"),
              let copySymbol = lookup("SecTaskCopyValueForEntitlement")
        else {
            return Snapshot(
                apiAvailable: false,
                apiError: "dlsym 未找到 SecTaskCreateFromSelf / SecTaskCopyValueForEntitlement（该运行时未导出）",
                values: [:],
                missingKeys: keys,
                keyErrors: []
            )
        }

        let create = unsafeBitCast(createSymbol, to: CreateFunction.self)
        let copyValue = unsafeBitCast(copySymbol, to: CopyValueFunction.self)

        guard let task = create(nil)?.takeRetainedValue() else {
            return Snapshot(
                apiAvailable: false,
                apiError: "SecTaskCreateFromSelf 返回 nil（进程未签名？）",
                values: [:],
                missingKeys: keys,
                keyErrors: []
            )
        }

        var values: [String: Any] = [:]
        var missing: [String] = []
        var errors: [String] = []
        for key in keys {
            var errorRef: Unmanaged<CFError>?
            let valueRef = copyValue(task, key as CFString, &errorRef)
            if let errorRef {
                let cfError = errorRef.takeRetainedValue()
                errors.append("\(key): \(String(describing: cfError))")
                continue
            }
            guard let valueRef else {
                missing.append(key)
                continue
            }
            values[key] = valueRef.takeRetainedValue()
        }
        return Snapshot(apiAvailable: true, apiError: nil, values: values, missingKeys: missing, keyErrors: errors)
    }
}

// MARK: - Code signature entitlements (Mach-O / SuperBlob)

private enum CodeSignatureEntitlements {
    struct Snapshot {
        var entitlements: [String: Any]?
        var detail: String
        var derOnly: Bool
    }

    static func read() -> Snapshot {
        guard let url = Bundle.main.executableURL else {
            return Snapshot(entitlements: nil, detail: "无法定位主可执行文件", derOnly: false)
        }
        guard let data = try? Data(contentsOf: url) else {
            return Snapshot(entitlements: nil, detail: "无法读取主可执行文件：\(url.path)", derOnly: false)
        }
        guard let slice = machOSlice(in: data) else {
            return Snapshot(entitlements: nil, detail: "无法解析 Mach-O（文件头异常）", derOnly: false)
        }
        guard let magic = data.uint32LE(slice.offset) else {
            return Snapshot(entitlements: nil, detail: "Mach-O 头读取失败", derOnly: false)
        }
        guard magic == 0xFEED_FACF else {
            return Snapshot(entitlements: nil, detail: String(format: "不是 64 位 Mach-O（magic=0x%08X）", magic), derOnly: false)
        }
        guard let commandCount = data.uint32LE(slice.offset + 16),
              let commandBytes = data.uint32LE(slice.offset + 20)
        else {
            return Snapshot(entitlements: nil, detail: "Mach-O load command 头读取失败", derOnly: false)
        }

        var cursor = slice.offset + 32
        let commandsEnd = cursor + Int(commandBytes)
        for _ in 0 ..< commandCount {
            guard cursor + 8 <= commandsEnd,
                  let command = data.uint32LE(cursor),
                  let commandSize = data.uint32LE(cursor + 4),
                  commandSize >= 8
            else {
                break
            }
            if command == 0x1D { // LC_CODE_SIGNATURE
                guard cursor + 16 <= data.count,
                      let dataOffset = data.uint32LE(cursor + 8),
                      let dataSize = data.uint32LE(cursor + 12)
                else {
                    return Snapshot(entitlements: nil, detail: "LC_CODE_SIGNATURE 读取失败", derOnly: false)
                }
                let signatureStart = slice.offset + Int(dataOffset)
                let signatureEnd = signatureStart + Int(dataSize)
                guard signatureStart >= 0, signatureEnd <= data.count else {
                    return Snapshot(entitlements: nil, detail: "签名数据超出文件范围", derOnly: false)
                }
                return parseSuperBlob(data: data, start: signatureStart, size: Int(dataSize))
            }
            cursor += Int(commandSize)
        }
        return Snapshot(entitlements: nil, detail: "未找到 LC_CODE_SIGNATURE（未签名或签名被剥离）", derOnly: false)
    }

    private static func parseSuperBlob(data: Data, start: Int, size: Int) -> Snapshot {
        guard let magic = data.uint32BE(start), magic == 0xFADE_0CC0 else {
            return Snapshot(entitlements: nil, detail: String(format: "CodeSigning SuperBlob magic 异常（0x%08X）", data.uint32BE(start) ?? 0), derOnly: false)
        }
        guard let count = data.uint32BE(start + 8) else {
            return Snapshot(entitlements: nil, detail: "SuperBlob 索引读取失败", derOnly: false)
        }
        var sawDER = false
        for index in 0 ..< Int(count) {
            let entry = start + 12 + index * 8
            guard entry + 8 <= start + size,
                  let type = data.uint32BE(entry),
                  let offset = data.uint32BE(entry + 4)
            else {
                break
            }
            if type == 7 { // CSSLOT_DER_ENTITLEMENTS
                sawDER = true
                continue
            }
            guard type == 5 else { continue } // CSSLOT_ENTITLEMENTS (XML plist)
            let blob = start + Int(offset)
            guard let blobMagic = data.uint32BE(blob), blobMagic == 0xFADE_7171,
                  let length = data.uint32BE(blob + 4), length >= 8
            else {
                continue
            }
            let payloadStart = blob + 8
            let payloadEnd = min(blob + Int(length), data.count)
            guard payloadStart < payloadEnd else { continue }
            let payload = Data(data[payloadStart ..< payloadEnd])
            if let plist = try? PropertyListSerialization.propertyList(from: payload, options: [], format: nil) as? [String: Any] {
                return Snapshot(entitlements: plist, detail: "CSSLOT_ENTITLEMENTS (XML plist)", derOnly: false)
            }
            return Snapshot(entitlements: nil, detail: "找到 CSSLOT_ENTITLEMENTS 但 plist 解析失败", derOnly: false)
        }
        if sawDER {
            return Snapshot(entitlements: nil, detail: "签名里只有 DER entitlements（CSSLOT_DER_ENTITLEMENTS），没有 XML plist 槽位；完整字典无法直接展开，请看 SecTask 已知 key 与描述文件", derOnly: true)
        }
        return Snapshot(entitlements: nil, detail: "签名里没有 entitlements blob", derOnly: false)
    }

    private static func machOSlice(in data: Data) -> (offset: Int, size: Int)? {
        guard let magic = data.uint32BE(0) else { return nil }
        if magic == 0xCAFE_BABE || magic == 0xCAFE_BABF {
            guard let count = data.uint32BE(4) else { return nil }
            var fallback: (Int, Int)?
            for index in 0 ..< Int(count) {
                let base = 8 + index * 20
                guard let cpu = data.uint32BE(base),
                      let offset = data.uint32BE(base + 8),
                      let size = data.uint32BE(base + 12)
                else {
                    break
                }
                if cpu == 0x0100_000C { // CPU_TYPE_ARM64
                    return (Int(offset), Int(size))
                }
                if fallback == nil {
                    fallback = (Int(offset), Int(size))
                }
            }
            return fallback
        }
        return (0, data.count)
    }
}

private extension Data {
    func uint32BE(_ offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        return (UInt32(self[offset]) << 24)
            | (UInt32(self[offset + 1]) << 16)
            | (UInt32(self[offset + 2]) << 8)
            | UInt32(self[offset + 3])
    }

    func uint32LE(_ offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        return UInt32(self[offset])
            | (UInt32(self[offset + 1]) << 8)
            | (UInt32(self[offset + 2]) << 16)
            | (UInt32(self[offset + 3]) << 24)
    }
}

// MARK: - embedded.mobileprovision

private enum EmbeddedProfileEntitlements {
    struct Snapshot {
        var found: Bool
        var name: String?
        var teamIdentifiers: [String]
        var expiresAt: String?
        var entitlements: [String: Any]?
        var detail: String
    }

    static func read() -> Snapshot {
        let url = Bundle.main.bundleURL.appendingPathComponent("embedded.mobileprovision")
        guard FileManager.default.fileExists(atPath: url.path) else {
            return Snapshot(found: false, name: nil, teamIdentifiers: [], expiresAt: nil, entitlements: nil, detail: "App 内没有 embedded.mobileprovision（未签名 / TrollStore / App Store 分发时通常没有）")
        }
        guard let data = try? Data(contentsOf: url) else {
            return Snapshot(found: true, name: nil, teamIdentifiers: [], expiresAt: nil, entitlements: nil, detail: "存在 embedded.mobileprovision 但读取失败")
        }
        guard let xmlStart = data.range(of: Data("<?xml".utf8)),
              let xmlEnd = data.range(of: Data("</plist>".utf8), options: [], in: xmlStart.lowerBound ..< data.endIndex)
        else {
            return Snapshot(found: true, name: nil, teamIdentifiers: [], expiresAt: nil, entitlements: nil, detail: "描述文件里找不到 XML plist（CMS 结构异常）")
        }
        let plistData = Data(data[xmlStart.lowerBound ..< xmlEnd.upperBound])
        guard let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any] else {
            return Snapshot(found: true, name: nil, teamIdentifiers: [], expiresAt: nil, entitlements: nil, detail: "描述文件 XML plist 解析失败")
        }
        let entitlements = plist["Entitlements"] as? [String: Any]
        let teamIdentifiers = plist["TeamIdentifier"] as? [String] ?? []
        var expiresAt: String?
        if let date = plist["ExpirationDate"] as? Date {
            expiresAt = ISO8601DateFormatter().string(from: date)
        }
        return Snapshot(
            found: true,
            name: plist["Name"] as? String,
            teamIdentifiers: teamIdentifiers,
            expiresAt: expiresAt,
            entitlements: entitlements,
            detail: entitlements == nil ? "描述文件里没有 Entitlements 字典" : "Entitlements（描述文件授予）"
        )
    }
}

// MARK: - Personal VPN probe

private func vpnProbeDescribe(error: Error?) -> String {
    guard let error else {
        return "nil（没有错误）"
    }
    let nsError = error as NSError
    var lines = [
        "raw: \(String(describing: error))",
        "domain: \(nsError.domain)",
        "code: \(nsError.code)",
        "localizedDescription: \(nsError.localizedDescription)",
    ]
    if !nsError.userInfo.isEmpty {
        lines.append("userInfo: \(nsError.userInfo)")
    }
    return lines.joined(separator: "\n")
}

private func vpnProbeLoadPreferences(_ manager: NEVPNManager) async -> Error? {
    await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in
        manager.loadFromPreferences { error in
            continuation.resume(returning: error)
        }
    }
}

private func vpnProbeSavePreferences(_ manager: NEVPNManager) async -> Error? {
    await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in
        manager.saveToPreferences { error in
            continuation.resume(returning: error)
        }
    }
}

private func vpnProbeRemovePreferences(_ manager: NEVPNManager) async -> Error? {
    await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in
        manager.removeFromPreferences { error in
            continuation.resume(returning: error)
        }
    }
}

// MARK: - View

struct VPNPermissionProbeView: View {
    @State private var secTaskSnapshot: SecTaskEntitlements.Snapshot?
    @State private var codeSignatureSnapshot: CodeSignatureEntitlements.Snapshot?
    @State private var profileSnapshot: EmbeddedProfileEntitlements.Snapshot?
    @State private var vpnProbeReport: String?
    @State private var vpnProbeRunning = false

    var body: some View {
        FormView {
            Section("签名 Entitlements（SecTask 实测）") {
                FormTextItem("SecTask API", secTaskSnapshot?.apiAvailable == true ? "可用（dlsym）" : "不可用")
                if let error = secTaskSnapshot?.apiError {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                FormTextItem("networkextension", vpnProbeKeyStatus(key: "com.apple.developer.networking.networkextension", in: secTaskSnapshot?.values))
                FormTextItem("vpn.api", vpnProbeKeyStatus(key: "com.apple.developer.networking.vpn.api", in: secTaskSnapshot?.values))
                if let snapshot = secTaskSnapshot, !snapshot.values.isEmpty, let text = optionalPlistText(snapshot.values) {
                    disclosureText("SecTask 已知 key（\(snapshot.values.count) 个）", text)
                }
                if let snapshot = secTaskSnapshot, !snapshot.missingKeys.isEmpty {
                    Text("未包含：\(snapshot.missingKeys.joined(separator: ", "))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if let snapshot = secTaskSnapshot, !snapshot.keyErrors.isEmpty {
                    Text(snapshot.keyErrors.joined(separator: "\n"))
                        .font(.caption2)
                        .foregroundStyle(.red)
                }
            }

            Section("签名二进制 Entitlements（CodeSignature）") {
                FormTextItem("来源", codeSignatureSnapshot?.detail ?? "读取中…")
                FormTextItem("networkextension", vpnProbeKeyStatus(key: "com.apple.developer.networking.networkextension", in: codeSignatureSnapshot?.entitlements))
                FormTextItem("vpn.api", vpnProbeKeyStatus(key: "com.apple.developer.networking.vpn.api", in: codeSignatureSnapshot?.entitlements))
                if let entitlements = codeSignatureSnapshot?.entitlements, let text = optionalPlistText(entitlements) {
                    disclosureText("完整签名 Entitlements 字典（\(entitlements.count) 个 key）", text)
                }
            }

            Section("描述文件 embedded.mobileprovision") {
                FormTextItem("状态", profileSnapshot?.found == true ? "存在" : "不存在")
                if let name = profileSnapshot?.name {
                    FormTextItem("Name", name)
                }
                if let teams = profileSnapshot?.teamIdentifiers, !teams.isEmpty {
                    FormTextItem("TeamIdentifier", teams.joined(separator: ", "))
                }
                if let expiresAt = profileSnapshot?.expiresAt {
                    FormTextItem("ExpirationDate", expiresAt)
                }
                FormTextItem("networkextension", vpnProbeKeyStatus(key: "com.apple.developer.networking.networkextension", in: profileSnapshot?.entitlements))
                FormTextItem("vpn.api", vpnProbeKeyStatus(key: "com.apple.developer.networking.vpn.api", in: profileSnapshot?.entitlements))
                if let detail = profileSnapshot?.detail {
                    Text(detail)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if let entitlements = profileSnapshot?.entitlements, let text = optionalPlistText(entitlements) {
                    disclosureText("描述文件 Entitlements 字典（\(entitlements.count) 个 key）", text)
                }
            }

            Section("Personal VPN 权限实测（NEVPNManager）") {
                Text("点击后在 App 进程里调用 NEVPNManager.shared().loadFromPreferences，再构造最小 IKEv2 配置（server=127.0.0.1，remoteIdentifier=sfi-adblock-probe，不填账号）并 saveToPreferences。可能出现系统 VPN 授权弹窗。成功时会立即 removeFromPreferences 清理，避免留下假 VPN 配置。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                FormButton {
                    Task { await runVPNProbe() }
                } label: {
                    Label(vpnProbeRunning ? "探测中…" : "运行 Personal VPN 探测", systemImage: "lock.shield")
                }
                .disabled(vpnProbeRunning)
                if let report = vpnProbeReport {
                    Text(report)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            Section {
                FormButton {
                    copyReport()
                } label: {
                    Label("复制全部结果", systemImage: "doc.on.doc")
                }
            }
        }
        .navigationTitle("VPN 权限探测")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        copyReport()
                    } label: {
                        Label("复制结果", systemImage: "doc.on.doc")
                    }
                }
            }
            .task {
                reloadEntitlements()
            }
    }

    private func reloadEntitlements() {
        // Read the profile first: every entitlement granted by the profile is also
        // worth asking SecTask about, which makes the runtime dump more complete.
        let profile = EmbeddedProfileEntitlements.read()
        profileSnapshot = profile
        var keys = vpnProbeEntitlementKeys
        if let entitlements = profile.entitlements {
            for key in entitlements.keys.sorted() where !keys.contains(key) {
                keys.append(key)
            }
        }
        secTaskSnapshot = SecTaskEntitlements.read(keys: keys)
        codeSignatureSnapshot = CodeSignatureEntitlements.read()
    }

    @ViewBuilder
    private func disclosureText(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(text)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func optionalPlistText(_ value: Any) -> String? {
        let text = vpnProbePlistText(value)
        return text.isEmpty ? nil : text
    }

    @MainActor
    private func runVPNProbe() async {
        vpnProbeRunning = true
        vpnProbeReport = "运行中…"
        var lines: [String] = []
        lines.append("bundleIdentifier: \(Bundle.main.bundleIdentifier ?? "nil")")
        lines.append("executable: \(Bundle.main.executableURL?.path ?? "nil")")

        let manager = NEVPNManager.shared()
        lines.append("NEVPNManager.shared(): \(String(describing: manager))")
        lines.append("isEnabled(before): \(manager.isEnabled)")

        let loadError = await vpnProbeLoadPreferences(manager)
        lines.append("loadFromPreferences: \(vpnProbeDescribe(error: loadError))")
        lines.append("protocolConfiguration(after load): \(String(describing: manager.protocolConfiguration))")

        let protocolConfiguration = NEVPNProtocolIKEv2()
        protocolConfiguration.serverAddress = "127.0.0.1"
        protocolConfiguration.remoteIdentifier = "sfi-adblock-probe"
        protocolConfiguration.disconnectOnSleep = false
        manager.protocolConfiguration = protocolConfiguration
        manager.localizedDescription = "sfi-adblock VPN probe"
        manager.isEnabled = true

        let saveError = await vpnProbeSavePreferences(manager)
        lines.append("saveToPreferences: \(vpnProbeDescribe(error: saveError))")
        lines.append("isEnabled(after save): \(manager.isEnabled)")

        if saveError == nil {
            let removeError = await vpnProbeRemovePreferences(manager)
            lines.append("cleanup removeFromPreferences: \(vpnProbeDescribe(error: removeError))")
        }

        vpnProbeReport = lines.joined(separator: "\n\n")
        vpnProbeRunning = false
    }

    private func makeReport() -> String {
        var report = "=== sfi-adblock VPN 权限探测 ===\n"
        if let info = Bundle.main.infoDictionary {
            report += "bundleIdentifier: \(info["CFBundleIdentifier"] as? String ?? "nil")\n"
        }
        report += "timestamp: \(ISO8601DateFormatter().string(from: Date()))\n"
        report += "\n[SecTask]\n"
        if let snapshot = secTaskSnapshot {
            report += "apiAvailable: \(snapshot.apiAvailable)\n"
            if let error = snapshot.apiError {
                report += "apiError: \(error)\n"
            }
            for key in vpnProbeEntitlementKeys {
                if let value = snapshot.values[key] {
                    report += "\(key) = PRESENT \(vpnProbeCompactDescription(value))\n"
                } else if snapshot.missingKeys.contains(key) {
                    report += "\(key) = ABSENT\n"
                }
            }
            if !snapshot.values.isEmpty {
                report += "\n[SecTask known values]\n\(vpnProbePlistText(snapshot.values))\n"
            }
        } else {
            report += "not loaded\n"
        }
        report += "\n[CodeSignature]\n"
        if let snapshot = codeSignatureSnapshot {
            report += "detail: \(snapshot.detail)\n"
            report += "derOnly: \(snapshot.derOnly)\n"
            if let entitlements = snapshot.entitlements {
                report += vpnProbePlistText(entitlements) + "\n"
            }
        } else {
            report += "not loaded\n"
        }
        report += "\n[embedded.mobileprovision]\n"
        if let snapshot = profileSnapshot {
            report += "found: \(snapshot.found)\n"
            if let name = snapshot.name { report += "name: \(name)\n" }
            if !snapshot.teamIdentifiers.isEmpty { report += "team: \(snapshot.teamIdentifiers.joined(separator: ", "))\n" }
            if let expiresAt = snapshot.expiresAt { report += "expiresAt: \(expiresAt)\n" }
            report += "detail: \(snapshot.detail)\n"
            if let entitlements = snapshot.entitlements {
                report += vpnProbePlistText(entitlements) + "\n"
            }
        } else {
            report += "not loaded\n"
        }
        report += "\n[NEVPNManager probe]\n\(vpnProbeReport ?? "not run")\n"
        return report
    }

    private func copyReport() {
        let report = makeReport()
        #if os(iOS)
            UIPasteboard.general.string = report
        #elseif os(macOS)
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(report, forType: .string)
        #endif
    }
}
#endif
