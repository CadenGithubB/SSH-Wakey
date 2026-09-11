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
            icon: "list.bullet.rectangle",
            title: "It remembers the connection details so you do not have to",
            body: """
            SSH-Wakey keeps a name, a username, an address and a port for each machine you need to \
            reach. Pick one from the list, press Connect, and it builds the ssh command for you.

            It saves no passwords and no keys. There is no sync, no network scanning and no \
            telemetry. The list is an ordinary file in your Library folder that only your account \
            can read, and you can open it and read it yourself.
            """),

        HelpTopic(
            icon: "terminal",
            title: "Connecting authenticates once, then hands you a shell",
            body: """
            Connect starts a single ssh process that logs in and then holds the connection open \
            without running anything on the other machine. Once it says Connected, Open in Terminal \
            starts an ordinary shell that joins that already-authenticated connection, so you are \
            never asked for the password a second time.

            The session belongs to SSH-Wakey while it runs. Quitting the app closes the connection, \
            and any Terminal window using it, which is why it asks before quitting.
            """),

        HelpTopic(
            icon: "lock.shield",
            title: "Your password is used once and then thrown away",
            body: """
            What you type goes straight to ssh through a channel that works exactly once. It is \
            never written to disk, never placed on a command line, and nothing keeps it after the \
            attempt ends.

            It is also never reused. If the machine rejects it, ssh asks again for a second login \
            method and SSH-Wakey does not answer, because that would be a silent retry with a \
            password already known to be wrong. You press Connect and type it again instead.

            While the password sheet is open it is kept out of screenshots and screen recordings.
            """),

        HelpTopic(
            icon: "lock.display",
            title: "Reaching a Mac that is waiting at the FileVault screen",
            body: """
            This is what the app is really for. A Mac with FileVault turned on does not finish \
            starting up by itself after a restart. It stops at a login screen while its disk is \
            still encrypted. That screen looks ordinary, but almost nothing is running behind it \
            yet, including the part of macOS that answers SSH.

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
            title: "What unlocking over SSH needs, arranged in advance",
            body: """
            All of this has to be set up while you can still reach the Mac. None of it can be done \
            once it is already sitting at the FileVault screen waiting.
            """,
            points: [
                HelpPoint(
                    title: "Remote Login, turned on beforehand",
                    body: "On the Mac you want to reach: System Settings ▸ General ▸ Sharing ▸ "
                        + "Remote Login. This is what lets anything connect over SSH at all."),
                HelpPoint(
                    title: "An Ethernet cable",
                    body: "Wi-Fi does not start until after the disk is unlocked, so a Mac on "
                        + "Wi-Fi alone is not on the network at that screen. A cable is the "
                        + "difference between reaching it and not."),
                HelpPoint(
                    title: "An account that can unlock FileVault",
                    body: "The password has to belong to a user who is allowed to unlock FileVault "
                        + "on that Mac. Usually that is the account that set it up."),
                HelpPoint(
                    title: "One deliberate rehearsal",
                    body: "Restart that Mac on purpose and unlock it over SSH while you are still "
                        + "sitting next to it. Finding the gap then is much better than finding it "
                        + "during a real problem."),
            ]),

        HelpTopic(
            icon: "arrow.clockwise",
            title: "Ways in that do not need any of that",
            body: "These work on any version of macOS.",
            points: [
                HelpPoint(
                    title: "Restart in a way that skips the lock screen",
                    body: "Before a planned restart, run this on the Mac you are about to restart, "
                        + "instead of restarting normally:\n\nsudo fdesetup authrestart\n\nIt saves "
                        + "a one-time unlock key, so the Mac starts straight past the FileVault "
                        + "screen and comes back on the network by itself."),
                HelpPoint(
                    title: "Have someone unlock it",
                    body: "Anyone at the keyboard can type the password. SSH works normally from "
                        + "that point on, which is when this app becomes useful."),
                HelpPoint(
                    title: "Hardware that can see the screen",
                    body: "A KVM switch, a remote management card, or a device management tool can "
                        + "reach the startup screen directly. An SSH app cannot."),
            ]),

        HelpTopic(
            icon: "network",
            title: "macOS asks before letting it onto your network",
            body: """
            macOS makes every app ask permission before it can reach other devices on your own \
            network, and the first time SSH-Wakey tries you get a prompt. That permission covers the \
            ssh program too, because SSH-Wakey is what starts it.

            If the prompt was dismissed, or answered with Don't Allow, every attempt to reach an \
            address on your network fails in exactly the same way as a machine that is switched \
            off. It is worth ruling out before going to look at the other Mac.
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
            title: "When a connection does not work",
            body: """
            A sleeping Mac usually does not answer, and a Mac that gets its address automatically \
            can be given a different one after a restart. Check that it is awake, on the same \
            network as this Mac, and still at the address you saved.

            The two kinds of failure mean different things. Refused means something answered and \
            turned you away, which usually means Remote Login is off. Timed out or unreachable \
            means nothing answered at all.

            Whatever ssh reported is under Show details, word for word.
            """),
    ]
}

/// The "What SSH-Wakey does" sheet.
struct HelpSheet: View {
    var onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("What SSH-Wakey does")
                    .font(.headline)
                Text("How it connects, what it does with your password, and what it needs from "
                     + "the other machine.")
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
