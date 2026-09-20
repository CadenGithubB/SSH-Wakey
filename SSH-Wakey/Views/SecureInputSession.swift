import Carbon.HIToolbox

@MainActor
final class SecureInputSession {
    private var isHolding = false
    var isActive: Bool { isHolding }
    func acquire() {
        guard !isHolding, EnableSecureEventInput() == noErr else { return }
        isHolding = true
    }
    func release() {
        guard isHolding else { return }
        DisableSecureEventInput()
        isHolding = false
    }
}
