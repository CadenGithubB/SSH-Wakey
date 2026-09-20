import AppKit
import Carbon.HIToolbox
import Foundation

/// A native secure popup used exclusively inside the sandboxed password-entry process.
/// There is deliberately no SwiftUI String binding or callback carrying a password.
/// AppKit's internal field storage cannot be promised to be explicitly erasable.
@MainActor
enum PasswordPromptView {
    private enum InputError: LocalizedError {
        case invalidPassword
        var errorDescription: String? {
            "Enter a nonempty password of at most 1,022 UTF-8 bytes, without newline or NUL characters."
        }
    }
    static func collect(authorization: PasswordAuthorization) -> SecureBuffer? {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        // The XPC service starts without NSApplication.run
        // or SwiftUI's app lifecycle. Complete native application startup before
        // running a modal event loop so activation and accessibility are ready.
        application.finishLaunching()
        let alert = NSAlert()
        alert.messageText = "Password for \(authorization.grant.context.destination)"
        alert.informativeText = "The host key has been verified. Enter this Mac's account password to \(authorization.grant.context.action.lowercased())."
        alert.addButton(withTitle: authorization.grant.context.action)
        alert.addButton(withTitle: "Cancel")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        field.placeholderString = "Remote Mac password"
        field.maximumNumberOfLines = 1
        field.isAutomaticTextCompletionEnabled = false
        field.allowsEditingTextAttributes = false
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        let secureInput = SecureInputSession()
        secureInput.acquire()
        guard secureInput.isActive else { return nil }
        let notifications = NotificationCenter.default
        let active = notifications.addObserver(forName: NSApplication.didBecomeActiveNotification,
            object: nil, queue: .main) { _ in
                MainActor.assumeIsolated {
                    secureInput.acquire()
                    if !secureInput.isActive { application.abortModal() }
                }
            }
        let inactive = notifications.addObserver(forName: NSApplication.didResignActiveNotification,
            object: nil, queue: .main) { _ in MainActor.assumeIsolated { secureInput.release() } }
        // The app's cancellation or exit closes the authorization connection.
        // This timer also enforces a bounded lifetime while the native modal runs.
        let timer = Timer(timeInterval: 0.2, repeats: true) { _ in
            MainActor.assumeIsolated {
                if !authorization.isValid || (application.isActive && !secureInput.isActive) {
                    application.abortModal()
                }
            }
        }
        RunLoop.main.add(timer, forMode: .modalPanel)
        defer {
            timer.invalidate()
            notifications.removeObserver(active)
            notifications.removeObserver(inactive)
            field.currentEditor()?.string = ""
            field.stringValue = ""
            alert.window.orderOut(nil)
            secureInput.release()
        }
        application.activate(ignoringOtherApps: true)
        guard authorization.isValid, alert.runModal() == .alertFirstButtonReturn,
              authorization.isValid, secureInput.isActive else { return nil }
        do {
            // This temporary Cocoa/Swift bridge is confined to the process that
            // exits after submission. No ordinary UTF-8 Array is introduced.
            return try autoreleasepool {
                field.validateEditing()
                let value = field.stringValue
                guard AskpassProtocol.validPassword(value) else { throw InputError.invalidPassword }
                return try SecureBuffer(value)
            }
        } catch {
            field.currentEditor()?.string = ""
            field.stringValue = ""
            let failure = NSAlert()
            failure.messageText = "The password was not sent"
            failure.informativeText = error.localizedDescription
            failure.runModal()
            return nil
        }
    }
}
