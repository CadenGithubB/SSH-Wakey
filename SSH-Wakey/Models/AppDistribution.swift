import Foundation

/// Which copy of the app this binary is.
///
/// Standard and Managed share one source tree. The only difference is a compile
/// flag baked into the signed app. A configuration profile cannot change it.
enum AppDistribution {

    #if SSHWAKEY_MANAGED_DISTRIBUTION
    static let isManagedBuild = true
    #else
    static let isManagedBuild = false
    #endif

    static let standardBundleIdentifier = "com.CadenGithubB.sshwakey"
    static let managedBundleIdentifier = "com.CadenGithubB.sshwakey.managed"
    /// Preference domain Jamf writes. Only the Managed build reads it.
    static let managedPreferenceDomain = managedBundleIdentifier

    static var supportFolderName: String {
        isManagedBuild ? "SSH-Wakey Managed" : "SSH-Wakey"
    }

    static var windowTitle: String {
        isManagedBuild ? "SSH-Wakey Managed" : "SSH-Wakey"
    }
}
