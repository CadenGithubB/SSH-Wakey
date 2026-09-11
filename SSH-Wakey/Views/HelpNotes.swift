import SwiftUI

/// One reason a connection fails, written for someone meeting the problem for
/// the first time.
struct HelpTopic: Identifiable {
    let id = UUID()
    let icon: String
    let title: String
    let body: String
    var points: [HelpPoint] = []
}

struct HelpPoint: Identifiable {
    let id = UUID()
    let title: String
    let body: String
}

/// Plain-language explanations shown in the app, kept in one place so they stay
/// consistent with the README.
enum HelpNotes {

    static let passwordNote = """
    The password is used once, for this connection attempt only. It is never written to disk, never \
    placed in a command line, and never kept after the attempt finishes.
    """

    static let topics: [HelpTopic] = [
        HelpTopic(
            icon: "lock.display",
            title: "The Mac restarted and is asking for a password on its own screen",
            body: """
            A Mac with FileVault turned on does not finish starting up by itself. It stops at a \
            login screen while its disk is still encrypted. That screen looks ordinary, but almost \
            nothing is running behind it yet, including the part of macOS that answers SSH.

            Whether you can reach a Mac sitting there depends on which version of macOS is on it. \
            The version on this Mac makes no difference.
            """,
            points: [
                HelpPoint(
                    title: "macOS 26 (Tahoe) or newer: you can get in",
                    body: "Apple added a way to unlock the disk over SSH. Connect the way you "
                        + "normally would and enter the password for an account on that Mac. That "
                        + "password unlocks the disk and lets it carry on starting up. There is "
                        + "nothing special to switch on in SSH-Wakey.\n\nThe connection will drop a "
                        + "second or two after it succeeds. That is not a failure. The Mac closes "
                        + "it while it finishes starting. Wait about half a minute and connect "
                        + "again for a normal session."),
                HelpPoint(
                    title: "macOS 15 (Sequoia) or older: you cannot, and neither can anything else",
                    body: "No SSH server is running at that screen, so there is nothing to connect "
                        + "to. Someone has to unlock that Mac at its own keyboard. Once macOS has "
                        + "started, SSH works normally."),
            ]),

        HelpTopic(
            icon: "checklist",
            title: "Unlocking over SSH needs setting up first",
            body: """
            All of this has to be arranged while you can still reach the Mac. None of it can be \
            done once it is already sitting at the FileVault screen waiting.
            """,
            points: [
                HelpPoint(
                    title: "Turn on Remote Login, in advance",
                    body: "On the Mac you want to reach: System Settings ▸ General ▸ Sharing ▸ "
                        + "Remote Login. This is what lets anything connect over SSH at all."),
                HelpPoint(
                    title: "Plug it into Ethernet",
                    body: "Wi-Fi does not start until after the disk is unlocked, so a Mac on "
                        + "Wi-Fi alone simply is not on the network at that screen. A cable is the "
                        + "difference between reaching it and not."),
                HelpPoint(
                    title: "Know which account to use",
                    body: "The password has to belong to a user who is allowed to unlock FileVault "
                        + "on that Mac. Usually that is the account that set it up."),
                HelpPoint(
                    title: "Try it once on purpose",
                    body: "Restart that Mac deliberately and unlock it over SSH while you are still "
                        + "sitting next to it. Finding the gap then is much better than finding it "
                        + "during a real problem."),
            ]),

        HelpTopic(
            icon: "arrow.clockwise",
            title: "If unlocking over SSH is not an option",
            body: "These work on any version of macOS.",
            points: [
                HelpPoint(
                    title: "Restart it in a way that skips the lock screen",
                    body: "Before a planned restart, run this on the Mac you are going to restart, "
                        + "instead of restarting normally:\n\nsudo fdesetup authrestart\n\nIt saves "
                        + "a one-time unlock key, so the Mac starts straight past the FileVault "
                        + "screen and comes back on the network by itself."),
                HelpPoint(
                    title: "Have someone unlock it",
                    body: "Anyone at the keyboard can type the password. SSH works normally from "
                        + "that point on, which is when this app becomes useful."),
                HelpPoint(
                    title: "Use hardware that can see the screen",
                    body: "A KVM switch, a remote management card, or a device management tool can "
                        + "reach the startup screen directly. An SSH app cannot."),
            ]),

        HelpTopic(
            icon: "network",
            title: "macOS has not let SSH-Wakey onto your local network",
            body: """
            macOS asks every app for permission before it can reach other devices on your own \
            network, and the first time SSH-Wakey tries, you get a prompt. That permission covers \
            the ssh program too, because SSH-Wakey is what starts it.

            If that prompt was dismissed, or answered with Don't Allow, every attempt to reach an \
            address on your network fails in exactly the same way as a machine that is switched \
            off. It is worth ruling out before you go looking at the other Mac.
            """,
            points: [
                HelpPoint(
                    title: "Where to check",
                    body: "System Settings ▸ Privacy & Security ▸ Local Network, and make sure "
                        + "SSH-Wakey is switched on. The button below opens it. If you have just "
                        + "turned it on, try connecting again."),
            ]),

        HelpTopic(
            icon: "powerplug",
            title: "The other machine is off, asleep, or somewhere else",
            body: """
            A sleeping Mac usually does not answer, and a Mac that gets its address automatically \
            can be given a different one after a restart. Check that it is awake, on the same \
            network as this Mac, and still at the address you saved.

            The two failures say different things. Refused means something answered and turned you \
            away, which usually means Remote Login is off. Timed out or unreachable means nothing \
            answered at all.
            """),
    ]
}

/// The "Why can't I connect?" sheet.
struct HelpSheet: View {
    var onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Why can't I connect?")
                    .font(.headline)
                Text("The usual reasons, and what to do about each one.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 20)
            .padding(.top, 20)
            .padding(.bottom, 14)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    ForEach(Array(HelpNotes.topics.enumerated()), id: \.element.id) { index, topic in
                        VStack(alignment: .leading, spacing: 10) {
                            Label {
                                Text(topic.title)
                                    .font(.system(size: 13, weight: .semibold))
                                    .fixedSize(horizontal: false, vertical: true)
                            } icon: {
                                Image(systemName: topic.icon).foregroundStyle(.tint)
                            }

                            Text(topic.body)
                                .font(.system(size: 12))
                                .fixedSize(horizontal: false, vertical: true)

                            ForEach(topic.points) { point in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(point.title)
                                        .font(.system(size: 12, weight: .semibold))
                                        .fixedSize(horizontal: false, vertical: true)
                                    Text(point.body)
                                        .font(.system(size: 12))
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                .padding(.leading, 22)
                            }

                            if topic.icon == "network" {
                                Button("Open Local Network Settings") {
                                    SystemSettings.openLocalNetworkPrivacy()
                                }
                                .controlSize(.small)
                                .padding(.leading, 22)
                            }
                        }

                        if index < HelpNotes.topics.count - 1 { Divider() }
                    }
                }
                .padding(20)
            }

            Divider()

            HStack {
                Spacer()
                Button("Done", action: onDismiss)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 560, height: 620)
    }
}

/// Deep links into System Settings panes the app points people at.
enum SystemSettings {
    static let localNetworkPrivacyURL = URL(
        string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork")!

    static func openLocalNetworkPrivacy() {
        NSWorkspace.shared.open(localNetworkPrivacyURL)
    }
}
