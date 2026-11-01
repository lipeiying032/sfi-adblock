import Foundation
import Libbox
import Library
import SwiftUI
import UniformTypeIdentifiers
#if os(iOS)
    import FileProvider
    import UIKit
#elseif os(macOS)
    import ServiceManagement
#endif

private struct MITMCAInfo: Codable {
    var exists: Bool
    var fingerprint: String?
    var notAfter: String?
    var subject: String?
    var pem: String?
    var error: String?
}

private struct MITMStats: Codable {
    var enabled: Bool
    var active: Bool
    var caReady: Bool
    var modules: Int
    var hosts: Int
    var rewrites: Int
    var rules: Int
    var intercepted: Int64
    var rewritten: Int64
    var blocked: Int64
    var fallbacks: Int64
    var activeConnections: Int64
    var caTrusted: Bool?
    var intercepting: Bool?
    var lowMemory: Bool?
    var lastError: String?
}

private struct MITMModuleInfo: Codable, Identifiable {
    var id: String
    var name: String
    var description: String?
    var enabled: Bool
    var hosts: Int
    var excludes: Int
    var rewrites: Int
    var rules: Int
    var scripts: Int
    var skipped: Int?
    var ignored: [String]?
}

private struct MITMRewriteInfo: Codable, Identifiable {
    var pattern: String
    var replacement: String?
    var action: String
    var module: String
    var id: String { pattern + action + module + (replacement ?? "") }
}

private struct MITMRuleInfo: Codable, Identifiable {
    var kind: String
    var value: String
    var action: String
    var module: String
    var id: String { kind + value + module }
}

private struct MITMRulesViewData: Codable {
    var hosts: [String]
    var excludes: [String]
    var rewrites: [MITMRewriteInfo]
    var rules: [MITMRuleInfo]
    var modules: [String]
}

private func mitmCADirectoryPath() -> String {
    FilePath.sharedDirectory.appendingPathComponent("mitm/ca", isDirectory: true).path
}

private func mitmModulesDirectoryPath() -> String {
    FilePath.sharedDirectory.appendingPathComponent("mitm/modules", isDirectory: true).path
}

/// gomobile exposes Go `(string, error)` functions as C functions taking an
/// `NSError**` out parameter, so they must be bridged manually instead of `try`.
private func libboxMITMCallString(_ call: (NSErrorPointer) -> String?) throws -> String {
    var callError: NSError?
    let result = call(&callError)
    if let callError {
        throw callError
    }
    guard let result else {
        throw NSError(domain: "io.nekohasekai.sfa.mitm", code: 1, userInfo: [NSLocalizedDescriptionKey: "Libbox returned no result"])
    }
    return result
}

private func libboxMITMCallBool(_ call: (NSErrorPointer) -> Bool) throws {
    var callError: NSError?
    let result = call(&callError)
    if let callError {
        throw callError
    }
    guard result else {
        throw NSError(domain: "io.nekohasekai.sfa.mitm", code: 1, userInfo: [NSLocalizedDescriptionKey: "Libbox reported failure"])
    }
}

private func writeCAMobileConfig(pem: String) -> URL? {
    let base64 = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") && !$0.isEmpty }.joined()
    let content = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>PayloadContent</key>
      <array>
        <dict>
          <key>PayloadCertificateFileName</key><string>sfi-adblock-ca.cer</string>
          <key>PayloadContent</key><data>\(base64)</data>
          <key>PayloadDescription</key><string>sfi-adblock MITM root CA</string>
          <key>PayloadDisplayName</key><string>sfi-adblock CA</string>
          <key>PayloadIdentifier</key><string>io.nekohasekai.sfa.mitm.ca</string>
          <key>PayloadType</key><string>com.apple.security.root</string>
          <key>PayloadUUID</key><string>\(UUID().uuidString)</string>
          <key>PayloadVersion</key><integer>1</integer>
        </dict>
      </array>
      <key>PayloadDisplayName</key><string>sfi-adblock CA</string>
      <key>PayloadIdentifier</key><string>io.nekohasekai.sfa.mitm</string>
      <key>PayloadRemovalDisallowed</key><false/>
      <key>PayloadType</key><string>Configuration</string>
      <key>PayloadUUID</key><string>\(UUID().uuidString)</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
    </plist>
    """
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("sfi-adblock-ca.mobileconfig")
    do {
        try content.write(to: url, atomically: true, encoding: .utf8)
        return url
    } catch {
        return nil
    }
}

@MainActor
public struct CoreView: View {
    @Environment(\.scenePhase) private var scenePhase
    @EnvironmentObject private var environments: ExtensionEnvironments
    @State private var isLoading = true
    @State private var alert: AlertState?

    @State private var disableDeprecatedWarnings = false
    @State private var mitmEnabled = false
    @State private var mitmCAForce = false
    @State private var mitmCAInfo: MITMCAInfo?
    @State private var mitmStats: MITMStats?
    @State private var mitmModules: [MITMModuleInfo] = []
    @State private var mitmRules: MITMRulesViewData?
    @State private var mitmShowImporter = false
    @State private var mitmShowURLImport = false
    @State private var mitmImportURL = ""
    @State private var mitmCAExportURL: URL?
    @State private var mitmCAExportFingerprint: String?

    @State private var version = ""
    @State private var dataSize: String?
    @State private var dataSizeLoaded = false

    #if os(macOS)
        @State private var helperUnavailable = false
    #endif

    public init() {}
    public var body: some View {
        Group {
            if isLoading {
                ProgressView().onAppear {
                    Task {
                        await loadSettings()
                    }
                }
            } else {
                FormView {
                    FormTextItem("Version", version)
                    if let dataSize {
                        FormTextItem("Data Size", dataSize)
                    } else if !dataSizeLoaded {
                        HStack {
                            Text("Data Size")
                            Spacer()
                            ProgressView()
                        }
                    } else {
                        #if os(macOS)
                            HStack {
                                Text("Data Size")
                                Spacer()
                                Text("Unavailable")
                                    .foregroundStyle(.red)
                                    .onTapGesture {
                                        alert = helperRequiredAlert()
                                    }
                            }
                        #endif
                    }

                    Section("MITM Ad Block") {
                        FormToggle("Enable MITM Ad Block", "Decrypt only the hosts imported from Shadowrocket modules. Default off; restart the tunnel to apply.", $mitmEnabled) { newValue in
                            await updateMITMEnabled(newValue)
                        }
                        FormTextItem("Status", mitmStatusText)
                        FormTextItem("CA", mitmCAStatusText)
                        FormTextItem("CA Trust", mitmTrustText)
                        FormTextItem("Memory", mitmMemoryText)
                        if let fingerprint = mitmCAInfo?.fingerprint {
                            FormTextItem("CA SHA-256", fingerprint)
                        }
                        if let lastError = mitmStats?.lastError, !lastError.isEmpty {
                            FormTextItem("Last Error", lastError)
                        }
                        FormToggle("Force Decrypt (CA trust unchecked)", "Decrypt matched hosts even when the CA trust check fails. Only for builds where the installed profile cannot be verified.", $mitmCAForce) { newValue in
                            await updateMITMCAForce(newValue)
                        }
                        FormButton {
                            Task { await generateMITMCA() }
                        } label: {
                            Label("Generate / Rotate CA", systemImage: "key.fill")
                        }
                        if mitmCAInfo?.exists == true {
                            FormButton {
                                copyMITMCertificate()
                            } label: {
                                Label("Copy CA Certificate", systemImage: "doc.on.doc")
                            }
                            if #available(iOS 16.0, *), let exportURL = mitmCAExportURL {
                                ShareLink(item: exportURL) {
                                    Label("Export CA (.mobileconfig)", systemImage: "square.and.arrow.up")
                                }
                            }
                            FormButton(role: .destructive) {
                                Task { await deleteMITMCA() }
                            } label: {
                                Label("Delete CA", systemImage: "trash")
                            }
                        }
                        Text("After generating the CA, export or copy it, install the profile, then enable full trust in Settings → General → About → Certificate Trust Settings. Decryption only starts once the tunnel can verify that trust; tap Restart Tunnel afterwards.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        FormTextItem("Intercepted", "\(mitmStats?.intercepted ?? 0)")
                        FormTextItem("Rewrites", "\(mitmStats?.rewritten ?? 0)")
                        FormTextItem("Rule Blocks", "\(mitmStats?.blocked ?? 0)")
                        FormTextItem("Fallbacks", "\(mitmStats?.fallbacks ?? 0)")
                        FormTextItem("Active Connections", "\(mitmStats?.activeConnections ?? 0)")
                        if mitmEnabled, environments.extensionProfile?.status.isConnected == true {
                            FormButton {
                                Task {
                                    await restartIfConnected()
                                    await refreshMITMStatus()
                                }
                            } label: {
                                Label("Restart Tunnel", systemImage: "arrow.clockwise")
                            }
                        }
                    }

                    Section("MITM Modules") {
                        FormButton {
                            mitmShowImporter = true
                        } label: {
                            Label("Import .sgmodule", systemImage: "square.and.arrow.down")
                        }
                        FormButton {
                            mitmShowURLImport = true
                        } label: {
                            Label("Import from URL", systemImage: "link")
                        }
                        if mitmModules.isEmpty {
                            Text("No modules imported. MITM stays idle until a module provides [MITM] hosts.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(mitmModules) { module in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text(module.name)
                                        Spacer()
                                        Toggle("", isOn: Binding(get: { module.enabled }, set: { value in
                                            Task { await setModuleEnabled(module, enabled: value) }
                                        }))
                                        .labelsHidden()
                                    }
                                    Text(moduleSummary(module))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Button(role: .destructive) {
                                        Task { await deleteModule(module) }
                                    } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                    .font(.caption)
                                }
                            }
                        }
                        if let rules = mitmRules {
                            NavigationLink(destination: MITMRulesListView(rules: rules)) {
                                Label("View MITM Rules (\(rules.hosts.count) hosts · \(rules.rewrites.count) rewrites)", systemImage: "list.bullet")
                            }
                        }
                    }

                    if Variant.isBeta {
                        FormToggle("Disable Deprecated Warnings", "Do not show warnings about usages of deprecated features.", $disableDeprecatedWarnings, header: "Beta Settings") {
                            newValue in
                            await SharedPreferences.disableDeprecatedWarnings.set(newValue)
                        }
                    }

                    Section("Working Directory") {
                        #if os(macOS)
                            if !Variant.useSystemExtension {
                                FormButton {
                                    NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: FilePath.workingDirectory.relativePath)
                                } label: {
                                    Label("Open", systemImage: "macwindow.and.cursorarrow")
                                }
                            }
                        #elseif os(iOS)
                            if #available(iOS 16.0, *) {
                                FormButton {
                                    Task {
                                        await openInFilesApp()
                                    }
                                } label: {
                                    Label("Browse", systemImage: "folder.fill")
                                }
                            }
                        #endif
                        FormButton(role: .destructive) {
                            Task {
                                await confirmDestroyWorkingDirectory()
                            }
                        } label: {
                            Label("Destroy", systemImage: "trash.fill")
                        }
                        .foregroundColor(.red)
                    }
                }
            }
        }
        .navigationTitle("Core")
        .alert($alert)
        .onAppear {
            guard !isLoading else {
                return
            }
            Task {
                await refreshWorkingDirectorySize()
            }
        }
        .onChangeCompat(of: scenePhase) { newValue in
            guard newValue == .active, !isLoading else {
                return
            }
            Task {
                await refreshWorkingDirectorySize()
            }
        }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if Task.isCancelled {
                    return
                }
                await refreshMITMStatus()
            }
        }
        .fileImporter(isPresented: $mitmShowImporter, allowedContentTypes: [UTType(filenameExtension: "sgmodule") ?? .data, .plainText, .data], allowsMultipleSelection: true) { result in
            Task { await importModules(result) }
        }
        .sheet(isPresented: $mitmShowURLImport) {
            NavigationView {
                Form {
                    Section {
                        #if os(iOS)
                            TextField("https://example.com/module.sgmodule", text: $mitmImportURL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .keyboardType(.URL)
                        #else
                            TextField("https://example.com/module.sgmodule", text: $mitmImportURL)
                                .autocorrectionDisabled()
                        #endif
                    } header: {
                        Text("Module URL")
                    } footer: {
                        Text("The .sgmodule content is downloaded and stored in the app group.")
                    }
                    Section {
                        Button("Import") {
                            Task { await importModuleFromURL() }
                        }
                        .disabled(mitmImportURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
                .navigationTitle("Import from URL")
                #if os(iOS)
                    .navigationBarTitleDisplayMode(.inline)
                #endif
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") {
                            mitmShowURLImport = false
                            mitmImportURL = ""
                        }
                    }
                }
            }
        }
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }

    private var mitmStatusText: String {
        if !mitmEnabled {
            return "Off"
        }
        if environments.extensionProfile?.status.isConnected != true {
            return "Tunnel off"
        }
        guard let stats = mitmStats else {
            return "Loading..."
        }
        if !stats.caReady {
            return "Waiting for CA"
        }
        if stats.caTrusted != true {
            return "CA not trusted"
        }
        if stats.intercepting != true {
            return "Waiting for restart"
        }
        if stats.lowMemory == true {
            return "Active · low memory, decryption paused"
        }
        return "Active · \(stats.hosts) hosts · \(stats.modules) modules"
    }

    private var mitmCAStatusText: String {
        guard let info = mitmCAInfo, info.exists else {
            return "Not generated"
        }
        if let error = info.error, !error.isEmpty {
            return "Error: \(error)"
        }
        return "Generated" + (info.notAfter.map { " · expires \($0)" } ?? "")
    }

    private var mitmTrustText: String {
        guard mitmCAInfo?.exists == true else {
            return "No certificate"
        }
        guard let stats = mitmStats, stats.caReady else {
            return "Unknown · start the tunnel"
        }
        if stats.caTrusted == true {
            return "Trusted"
        }
        return "Not trusted · install the profile, enable full trust, then Restart Tunnel"
    }

    private var mitmMemoryText: String {
        guard mitmEnabled, environments.extensionProfile?.status.isConnected == true, let stats = mitmStats else {
            return "Unknown"
        }
        return stats.lowMemory == true ? "Low · decryption paused" : "Normal"
    }

    private func updateMITMCAForce(_ newValue: Bool) async {
        await SharedPreferences.mitmCAForce.set(newValue)
        await restartIfConnected()
        await refreshMITMStatus()
    }

    private func updateMITMEnabled(_ newValue: Bool) async {
        await SharedPreferences.mitmEnabled.set(newValue)
        if newValue, !(mitmCAInfo?.exists == true) {
            alert = AlertState(title: "CA Certificate Required", message: "MITM is on but no CA exists yet.\n\n1. Tap Generate / Rotate CA.\n2. Export the .mobileconfig and install it as a profile.\n3. Enable full trust in Settings → General → About → Certificate Trust Settings.\n4. Restart the tunnel.\n\nWithout a trusted CA, HTTPS hosts in modules cannot be decrypted.")
        }
        await restartIfConnected()
        await refreshMITMStatus()
    }

    private func generateMITMCA() async {
        do {
            try libboxMITMCallBool { LibboxRequestMITMCA(mitmCADirectoryPath(), $0) }
            if environments.extensionProfile?.status.isConnected == true {
                await restartIfConnected()
                alert = AlertState(title: "Generating CA", message: "The tunnel is restarting. The new CA appears here in a few seconds; export and install it, then enable full trust.")
            } else {
                alert = AlertState(title: "CA queued", message: "Start the tunnel to finish generating the CA. The certificate is created in the tunnel process on its next start.")
            }
            await refreshMITMStatus()
        } catch {
            alert = AlertState(action: "generate CA", error: error)
        }
    }

    private func deleteMITMCA() async {
        do {
            try libboxMITMCallBool { LibboxRequestDeleteMITMCA(mitmCADirectoryPath(), $0) }
            if environments.extensionProfile?.status.isConnected == true {
                await restartIfConnected()
                alert = AlertState(title: "Deleting CA", message: "The tunnel is restarting and the CA will be removed.")
            } else {
                alert = AlertState(title: "Deletion queued", message: "The CA will be removed the next time the tunnel starts.")
            }
            await refreshMITMStatus()
        } catch {
            alert = AlertState(action: "delete CA", error: error)
        }
    }

    private func copyMITMCertificate() {
        guard let pem = mitmCAInfo?.pem else {
            return
        }
        #if os(iOS)
            UIPasteboard.general.string = pem
        #endif
    }

    private func restartIfConnected() async {
        guard let profile = environments.extensionProfile, profile.status.isConnected else {
            return
        }
        do {
            try await profile.restart()
        } catch {
            alert = AlertState(action: "restart tunnel", error: error)
        }
    }

    private func moduleSummary(_ module: MITMModuleInfo) -> String {
        var summary = "\(module.hosts) MITM hosts · \(module.rewrites) rewrites · \(module.rules) rules"
        if module.scripts > 0 {
            summary += " · \(module.scripts) script lines skipped"
        }
        if let skipped = module.skipped, skipped > 0 {
            summary += " · \(skipped) lines skipped"
        }
        if let ignored = module.ignored, !ignored.isEmpty {
            summary += " · ignored: \(ignored.joined(separator: ", "))"
        }
        return summary
    }

    private func importSummary(_ module: MITMModuleInfo) -> String {
        var summary = "\(module.name): \(module.hosts) MITM hosts, \(module.rewrites) rewrites, \(module.rules) rules"
        if module.scripts > 0 {
            summary += "\nIgnored \(module.scripts) lines in [Script] (JavaScript is not supported)"
        }
        if let skipped = module.skipped, skipped > 0 {
            summary += "\nIgnored \(skipped) unsupported lines (lookaround regex, header/body rewrite, templates)"
        }
        if let ignored = module.ignored, !ignored.isEmpty {
            summary += "\nIgnored sections: \(ignored.joined(separator: ", "))"
        }
        return summary
    }

    private func importModuleContent(_ content: String) throws -> String {
        let json = try libboxMITMCallString { LibboxImportMITMModule(mitmModulesDirectoryPath(), content, $0) }
        let info = try JSONDecoder().decode(MITMModuleInfo.self, from: Data(json.utf8))
        return importSummary(info)
    }

    private func importModules(_ result: Result<[URL], Error>) async {
        do {
            let urls = try result.get()
            var summaries: [String] = []
            for url in urls {
                let accessing = url.startAccessingSecurityScopedResource()
                defer {
                    if accessing {
                        url.stopAccessingSecurityScopedResource()
                    }
                }
                let content = try String(contentsOf: url, encoding: .utf8)
                summaries.append(try importModuleContent(content))
            }
            await refreshMITMData()
            await restartIfConnected()
            await refreshMITMStatus()
            alert = AlertState(title: "Module Imported", message: summaries.joined(separator: "\n\n"))
        } catch {
            alert = AlertState(action: "import module", error: error)
        }
    }

    private func importModuleFromURL() async {
        let trimmed = mitmImportURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), url.scheme == "https" || url.scheme == "http" else {
            alert = AlertState(title: "Invalid URL", message: "Enter an http(s) URL to a .sgmodule file.")
            return
        }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            guard let content = String(data: data, encoding: .utf8) else {
                throw NSError(domain: "sfi-adblock", code: 1, userInfo: [NSLocalizedDescriptionKey: "Module is not UTF-8 text"])
            }
            let summary = try importModuleContent(content)
            mitmShowURLImport = false
            await refreshMITMData()
            await restartIfConnected()
            await refreshMITMStatus()
            mitmImportURL = ""
            alert = AlertState(title: "Module Imported", message: summary)
        } catch {
            mitmShowURLImport = false
            alert = AlertState(action: "import module from URL", error: error)
        }
    }

    private func setModuleEnabled(_ module: MITMModuleInfo, enabled: Bool) async {
        do {
            _ = try libboxMITMCallString { LibboxSetMITMModuleEnabled(mitmModulesDirectoryPath(), module.id, enabled, $0) }
            await refreshMITMData()
            await restartIfConnected()
            await refreshMITMStatus()
        } catch {
            alert = AlertState(action: "update module", error: error)
        }
    }

    private func deleteModule(_ module: MITMModuleInfo) async {
        do {
            _ = try libboxMITMCallString { LibboxDeleteMITMModule(mitmModulesDirectoryPath(), module.id, $0) }
            await refreshMITMData()
            await restartIfConnected()
            await refreshMITMStatus()
        } catch {
            alert = AlertState(action: "delete module", error: error)
        }
    }

    /// Cheap refresh: runs on the 2s timer, only reads the CA certificate and
    /// the runtime counters persisted by the tunnel process.
    private nonisolated func refreshMITMStatus() async {
        let enabled = await SharedPreferences.mitmEnabled.get()
        let caForce = await SharedPreferences.mitmCAForce.get()
        let caJSON = LibboxMITMCAInfo(mitmCADirectoryPath())
        let statsJSON = LibboxMITMStats(mitmCADirectoryPath())
        let decoder = JSONDecoder()
        let caInfo = try? decoder.decode(MITMCAInfo.self, from: Data(caJSON.utf8))
        let stats = try? decoder.decode(MITMStats.self, from: Data(statsJSON.utf8))
        await MainActor.run {
            self.mitmEnabled = enabled
            self.mitmCAForce = caForce
            self.mitmCAInfo = caInfo
            self.mitmStats = stats
            if let caInfo, caInfo.exists, let pem = caInfo.pem, caInfo.fingerprint != self.mitmCAExportFingerprint {
                self.mitmCAExportURL = writeCAMobileConfig(pem: pem)
                self.mitmCAExportFingerprint = caInfo.fingerprint
            }
        }
    }

    /// Expensive refresh: reparses every imported module. Only called after an
    /// import / toggle / delete, on load, and when the app becomes active.
    private nonisolated func refreshMITMData() async {
        let modulesJSON = (try? libboxMITMCallString { LibboxListMITMModules(mitmModulesDirectoryPath(), $0) }) ?? "[]"
        let rulesJSON = (try? libboxMITMCallString { LibboxMITMRules(mitmModulesDirectoryPath(), $0) }) ?? "{}"
        let decoder = JSONDecoder()
        let modules = try? decoder.decode([MITMModuleInfo].self, from: Data(modulesJSON.utf8))
        let rules = try? decoder.decode(MITMRulesViewData.self, from: Data(rulesJSON.utf8))
        await MainActor.run {
            self.mitmModules = modules ?? []
            self.mitmRules = rules
        }
    }

    private nonisolated func loadSettings() async {
        if Variant.screenshotMode {
            await MainActor.run {
                version = "<redacted>"
                dataSize = LibboxFormatBytes(1000 * 1000 * 10)
                isLoading = false
            }
        } else {
            await MainActor.run {
                version = LibboxVersion()
                isLoading = false
            }
            await loadSettingsBackground()
        }
    }

    private nonisolated func loadSettingsBackground() async {
        let disableDeprecatedWarnings = await SharedPreferences.disableDeprecatedWarnings.get()
        await MainActor.run {
            self.disableDeprecatedWarnings = disableDeprecatedWarnings
        }
        await refreshMITMStatus()
        await refreshMITMData()
        await refreshWorkingDirectorySize()
    }

    private nonisolated func refreshWorkingDirectorySize() async {
        guard !Variant.screenshotMode else {
            return
        }
        #if os(macOS)
            let helperUnavailable = Variant.useSystemExtension && HelperServiceManager.rootHelperStatus != .enabled
        #endif
        let workingDirectory = FilePath.workingDirectory
        let dataSize: String? = await BlockingIO.run {
            #if os(macOS)
                if Variant.useSystemExtension {
                    if helperUnavailable {
                        return nil
                    }
                    guard let size = try? RootHelperClient.shared.getWorkingDirectorySize() else {
                        return nil
                    }
                    return LibboxFormatBytes(size)
                } else {
                    return (try? workingDirectory.formattedSize()) ?? "Unknown"
                }
            #else
                return (try? workingDirectory.formattedSize()) ?? "Unknown"
            #endif
        }
        await MainActor.run {
            #if os(macOS)
                self.helperUnavailable = helperUnavailable
            #endif
            self.dataSize = dataSize
            dataSizeLoaded = true
        }
    }

    private func confirmDestroyWorkingDirectory() async {
        #if os(macOS)
            if helperUnavailable {
                alert = helperRequiredAlert()
                return
            }
        #endif
        if environments.extensionProfile?.status.isConnected == true {
            alert = AlertState(
                title: String(localized: "Service is Running"),
                message: String(localized: "The service must be stopped before destroying the working directory."),
                primaryButton: .destructive(String(localized: "Stop Service and Continue")) { [self] in
                    Task {
                        await stopServiceAndDestroy()
                    }
                },
                secondaryButton: .cancel()
            )
        } else {
            await destroyWorkingDirectory()
        }
    }

    private func stopServiceAndDestroy() async {
        do {
            try await environments.extensionProfile!.stop()
            await destroyWorkingDirectory()
        } catch {
            alert = AlertState(action: "stop service before destroying working directory", error: error)
        }
    }

    private func destroyWorkingDirectory() async {
        do {
            let workingDirectory = FilePath.workingDirectory
            #if os(macOS)
                if Variant.useSystemExtension {
                    try await BlockingIO.run {
                        try RootHelperClient.shared.cleanWorkingDirectory()
                    }
                } else {
                    try await BlockingIO.run {
                        try Self.clearWorkingDirectoryContents(at: workingDirectory)
                    }
                }
            #else
                try await BlockingIO.run {
                    try Self.clearWorkingDirectoryContents(at: workingDirectory)
                }
                #if os(iOS)
                    if #available(iOS 16.0, *) {
                        await notifyFileProviderWorkingDirectoryChanged()
                    }
                #endif
            #endif
            isLoading = true
        } catch {
            alert = AlertState(action: "destroy working directory", error: error)
        }
    }

    private nonisolated static func clearWorkingDirectoryContents(at url: URL) throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }
        let contents = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)
        for item in contents {
            try FileManager.default.removeItem(at: item)
        }
    }

    #if os(macOS)
        private func helperRequiredAlert() -> AlertState {
            AlertState(
                title: String(localized: "Helper Service Required"),
                message: String(localized: "Managing working directory requires Helper Service."),
                primaryButton: .default(String(localized: "App Settings")) {
                    NotificationCenter.default.post(name: .navigateToSettingsPage, object: SettingsPage.app)
                },
                secondaryButton: .cancel(String(localized: "Ok"))
            )
        }
    #endif

    #if os(iOS)
        @available(iOS 16.0, *)
        private nonisolated func fileProviderManager() async throws -> NSFileProviderManager {
            let domains = try await NSFileProviderManager.domains()
            guard let domain = domains.first(where: { $0.identifier.rawValue == AppConfiguration.fileProviderDomainID }) else {
                throw NSError(domain: "CoreView", code: 0, userInfo: [NSLocalizedDescriptionKey: "File provider domain not found"])
            }
            guard let manager = NSFileProviderManager(for: domain) else {
                throw NSError(domain: "CoreView", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to get file provider manager"])
            }
            return manager
        }

        @available(iOS 16.0, *)
        private nonisolated func notifyFileProviderWorkingDirectoryChanged() async {
            do {
                let manager = try await fileProviderManager()
                try await manager.signalEnumerator(for: .rootContainer)
                try await manager.signalEnumerator(for: .workingSet)
            } catch {
                await MainActor.run {
                    alert = AlertState(action: "notify Files app about working directory changes", error: error)
                }
            }
        }

        @available(iOS 16.0, *)
        private nonisolated func openInFilesApp() async {
            do {
                let manager = try await fileProviderManager()
                try await manager.signalEnumerator(for: .workingSet)
                let url = try await manager.getUserVisibleURL(for: .rootContainer)
                guard let sharedURL = URL(string: "shareddocuments://\(url.path)") else {
                    throw NSError(domain: "CoreView", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create shared documents URL"])
                }
                await MainActor.run {
                    UIApplication.shared.open(sharedURL)
                }
            } catch {
                await MainActor.run {
                    alert = AlertState(action: "open working directory in Files", error: error)
                }
            }
        }
    #endif
}

private extension URL {
    func formattedSize() throws -> String? {
        guard let enumerator = FileManager.default.enumerator(
            at: self,
            includingPropertiesForKeys: [.totalFileAllocatedSizeKey]
        ) else {
            return nil
        }
        var size = 0
        while let url = enumerator.nextObject() as? URL {
            size += try url.resourceValues(forKeys: [.totalFileAllocatedSizeKey]).totalFileAllocatedSize ?? 0
        }
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        guard let byteCount = formatter.string(for: size) else {
            return nil
        }
        return byteCount
    }
}

private struct MITMRulesListView: View {
    let rules: MITMRulesViewData
    @State private var query = ""

    private var filteredHosts: [String] {
        guard !query.isEmpty else {
            return rules.hosts
        }
        return rules.hosts.filter { $0.localizedCaseInsensitiveContains(query) }
    }

    private var filteredRewrites: [MITMRewriteInfo] {
        guard !query.isEmpty else {
            return rules.rewrites
        }
        return rules.rewrites.filter {
            $0.pattern.localizedCaseInsensitiveContains(query) ||
                $0.action.localizedCaseInsensitiveContains(query) ||
                $0.module.localizedCaseInsensitiveContains(query)
        }
    }

    private var filteredRules: [MITMRuleInfo] {
        guard !query.isEmpty else {
            return rules.rules
        }
        return rules.rules.filter {
            $0.value.localizedCaseInsensitiveContains(query) ||
                $0.kind.localizedCaseInsensitiveContains(query) ||
                $0.module.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        List {
            Section("MITM Hosts (\(filteredHosts.count))") {
                ForEach(filteredHosts, id: \.self) { host in
                    Text(host)
                        .font(.system(.footnote, design: .monospaced))
                }
            }
            Section("MITM Exclusions (\(rules.excludes.count))") {
                ForEach(rules.excludes, id: \.self) { host in
                    Text(host)
                        .font(.system(.footnote, design: .monospaced))
                }
            }
            Section("URL Rewrite (\(filteredRewrites.count))") {
                ForEach(filteredRewrites) { rule in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(rule.pattern)
                            .font(.system(.footnote, design: .monospaced))
                        Text("\(rule.action) \(rule.replacement ?? "")")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        Text(rule.module)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Section("Rules (\(filteredRules.count))") {
                ForEach(filteredRules) { rule in
                    Text("\(rule.kind),\(rule.value),\(rule.action)")
                        .font(.system(.footnote, design: .monospaced))
                }
            }
        }
        .searchable(text: $query)
        .navigationTitle("MITM Rules")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}
