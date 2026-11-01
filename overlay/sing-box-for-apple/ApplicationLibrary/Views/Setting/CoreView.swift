import Foundation
import Libbox
import Library
import SwiftUI
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
    var lastError: String?
}

private func mitmCADirectoryPath() -> String {
    FilePath.sharedDirectory.appendingPathComponent("mitm/ca", isDirectory: true).path
}

@MainActor
public struct CoreView: View {
    @Environment(\.scenePhase) private var scenePhase
    @EnvironmentObject private var environments: ExtensionEnvironments
    @State private var isLoading = true
    @State private var alert: AlertState?

    @State private var disableDeprecatedWarnings = false
    @State private var mitmEnabled = false
    @State private var mitmCAInfo: MITMCAInfo?
    @State private var mitmStats: MITMStats?

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
                        if let fingerprint = mitmCAInfo?.fingerprint {
                            FormTextItem("CA SHA-256", fingerprint)
                        }
                        if let lastError = mitmStats?.lastError, !lastError.isEmpty {
                            FormTextItem("Last Error", lastError)
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
                            FormButton(role: .destructive) {
                                Task { await deleteMITMCA() }
                            } label: {
                                Label("Delete CA", systemImage: "trash")
                            }
                        }
                        Text("After generating the CA, install it as a profile, then enable full trust in Settings → General → About → Certificate Trust Settings. Restart the tunnel after any CA change.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        FormTextItem("Intercepted", "\(mitmStats?.intercepted ?? 0)")
                        FormTextItem("Rewrites", "\(mitmStats?.rewritten ?? 0)")
                        FormTextItem("Rule Blocks", "\(mitmStats?.blocked ?? 0)")
                        FormTextItem("Fallbacks", "\(mitmStats?.fallbacks ?? 0)")
                        FormTextItem("Active Connections", "\(mitmStats?.activeConnections ?? 0)")
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
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }

    private var mitmStatusText: String {
        if !mitmEnabled {
            return "Off"
        }
        guard let stats = mitmStats else {
            return "Loading..."
        }
        if stats.active {
            return "Active"
        }
        if !stats.caReady {
            return "Waiting for CA"
        }
        return "Waiting for restart"
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

    private func updateMITMEnabled(_ newValue: Bool) async {
        await SharedPreferences.mitmEnabled.set(newValue)
        await restartIfConnected()
        await refreshMITMStatus()
    }

    private func generateMITMCA() async {
        do {
            var requestError: NSError?
            if !LibboxRequestMITMCA(mitmCADirectoryPath(), &requestError), let requestError {
                throw requestError
            }
            await restartIfConnected()
            await refreshMITMStatus()
        } catch {
            alert = AlertState(action: "generate CA", error: error)
        }
    }

    private func deleteMITMCA() async {
        do {
            var requestError: NSError?
            if !LibboxRequestDeleteMITMCA(mitmCADirectoryPath(), &requestError), let requestError {
                throw requestError
            }
            await restartIfConnected()
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

    private nonisolated func refreshMITMStatus() async {
        let enabled = await SharedPreferences.mitmEnabled.get()
        let caJSON = LibboxMITMCAInfo(mitmCADirectoryPath())
        let statsJSON = LibboxMITMStats()
        let decoder = JSONDecoder()
        let caInfo = try? decoder.decode(MITMCAInfo.self, from: Data(caJSON.utf8))
        let stats = try? decoder.decode(MITMStats.self, from: Data(statsJSON.utf8))
        await MainActor.run {
            self.mitmEnabled = enabled
            self.mitmCAInfo = caInfo
            self.mitmStats = stats
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
