import Foundation

// `ssh` runs this same executable as its SSH_ASKPASS helper. That mode is
// selected purely by the environment of the process ssh spawns, never by a
// script or a marker file left on disk, and it has to finish before any UI
// framework is initialised. So it is the very first thing main does.
if let request = AskpassHelper.requestFromEnvironment() {
    AskpassHelper.serve(request)
}

SSHWakeyApp.main()
