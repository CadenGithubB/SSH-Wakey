import Foundation

/// Turns the free-text "extra SSH arguments" field into an argument array.
///
/// Two rules drive this file:
///
///  1. No shell is ever involved. The text is tokenised here and handed to
///     `Process.arguments` as an array, so there is no word splitting, no glob
///     expansion, no command substitution and no injection surface.
///  2. Options that would let `ssh` run another program, or that would fight
///     with the options SSH-Wakey sets itself, are refused with an explanation
///     rather than quietly dropped.
enum SSHArgumentParser {

    enum ParseError: LocalizedError, Equatable {
        case unterminatedQuote(Character)
        case trailingBackslash
        case controlCharacter
        case unexpectedOperand(String)
        case missingValue(String)
        case unknownOption(String)
        case reservedOption(String)
        case dangerousOption(String)
        case unsupportedKeyword(String)
        case invalidValue(String)

        var errorDescription: String? {
            switch self {
            case .unterminatedQuote(let quote):
                return "There is an unclosed \(quote) quote in the extra arguments."
            case .trailingBackslash:
                return "The extra arguments end with a stray backslash."
            case .controlCharacter:
                return "The extra arguments contain a control character."
            case .unexpectedOperand(let token):
                return "\"\(token)\" is not an option. The destination comes from the Username, Host and Port fields, so extra arguments may only contain ssh options."
            case .missingValue(let option):
                return "The option \(option) needs a value."
            case .unknownOption(let option):
                return "\(option) is not an ssh option that SSH-Wakey recognises."
            case .reservedOption(let option):
                return "\(option) is set by SSH-Wakey itself and cannot be overridden here."
            case .dangerousOption(let option):
                return "\(option) can make ssh run another program on this Mac, so it is not allowed."
            case .invalidValue(let option):
                return "The value for \(option) is outside SSH-Wakey’s supported connection settings."
            case .unsupportedKeyword(let option):
                return "\(option) is not one of the ssh options SSH-Wakey allows. It passes only a fixed set of safe connection options; if you need this one, it can be added to the allow list."
            }
        }
    }

    /// Options that ask `ssh` to execute something locally, or that redirect
    /// trust decisions away from the file SSH-Wakey verifies against.
    static let dangerousKeywords: Set<String> = [
        "proxycommand", "localcommand", "permitlocalcommand", "knownhostscommand",
        "pkcs11provider", "securitykeyprovider", "include", "match",
        "userknownhostsfile", "globalknownhostsfile", "xauthlocation",
    ]

    /// Options SSH-Wakey supplies from the connection fields or from its own
    /// session management. Letting them be set twice produces confusing results.
    /// `loglevel` is here because the app relies on `LogLevel=VERBOSE` to tell a
    /// successful login from a refused one.
    static let reservedKeywords: Set<String> = [
        "controlpath", "controlmaster", "controlpersist", "stricthostkeychecking",
        "numberofpasswordprompts", "batchmode", "user", "hostname", "port",
        "connecttimeout", "requesttty", "sessiontype", "forkafterauthentication",
        "loglevel",
    ]

    /// Extra settings cannot change authentication, trust, algorithms, forwarding,
    /// delegated credentials, agent lifetime, logging destinations, or transports.
    static let allowedKeywords: Set<String> = [
        "serveraliveinterval", "serveralivecountmax", "connectionattempts",
        "tcpkeepalive", "addressfamily", "identitiesonly",
    ]

    private static let dangerousFlags: Set<Character> = ["F", "I", "J"]
    private static let reservedFlags: Set<Character> = [
        "M", "S", "N", "f", "p", "l", "O", "W", "Q", "V", "G", "E", "s", "q", "y",
        "A", "a", "X", "x", "Y", "K", "k", "D", "L", "R", "g", "w", "c", "m",
        "t", "T", "n", "C", "b",
    ]
    private static let valueFlags: Set<Character> = ["i", "o"]
    private static let booleanFlags: Set<Character> = ["4", "6", "v"]

    /// Tokenise and check in one step. This is what callers should use.
    static func parse(_ text: String) throws -> [String] {
        let tokens = try tokenize(text)
        try validate(tokens)
        return tokens
    }

    /// Splits on whitespace, honouring single quotes, double quotes and
    /// backslash escapes. This is *only* quote handling; nothing is expanded.
    static func tokenize(_ text: String) throws -> [String] {
        var tokens: [String] = []
        var current = ""
        var hasCurrent = false
        var quote: Character?
        var escaped = false

        for character in text {
            if character.unicodeScalars.contains(where: { $0.properties.generalCategory == .control && $0 != "\t" && $0 != "\n" }) {
                throw ParseError.controlCharacter
            }
            if escaped {
                current.append(character)
                escaped = false
                continue
            }
            if character == "\\" && quote != "'" {
                escaped = true
                hasCurrent = true
                continue
            }
            if let open = quote {
                if character == open {
                    quote = nil
                } else {
                    current.append(character)
                }
                continue
            }
            if character == "'" || character == "\"" {
                quote = character
                hasCurrent = true
                continue
            }
            if character.isWhitespace {
                if hasCurrent { tokens.append(current) }
                current = ""
                hasCurrent = false
                continue
            }
            current.append(character)
            hasCurrent = true
        }

        if let open = quote { throw ParseError.unterminatedQuote(open) }
        if escaped { throw ParseError.trailingBackslash }
        if hasCurrent { tokens.append(current) }
        return tokens
    }

    /// Rejects operands, unknown flags, reserved flags and anything that could
    /// turn an ssh option into local command execution.
    static func validate(_ tokens: [String]) throws {
        var index = 0
        while index < tokens.count {
            let token = tokens[index]
            guard token.hasPrefix("-"), token.count > 1 else {
                throw ParseError.unexpectedOperand(token)
            }
            if token == "--" || token.hasPrefix("--") {
                throw ParseError.unknownOption(token)
            }

            let letters = Array(token.dropFirst())
            var consumedValue = false

            for (offset, letter) in letters.enumerated() {
                if dangerousFlags.contains(letter) {
                    throw ParseError.dangerousOption("-\(letter)")
                }
                if reservedFlags.contains(letter) {
                    throw ParseError.reservedOption("-\(letter)")
                }
                if valueFlags.contains(letter) {
                    let attached = String(letters[(offset + 1)...])
                    let value: String
                    if attached.isEmpty {
                        guard index + 1 < tokens.count else { throw ParseError.missingValue("-\(letter)") }
                        value = tokens[index + 1]
                        consumedValue = true
                    } else {
                        value = attached
                    }
                    if letter == "o" { try validateKeywordOption(value) }
                    if letter == "i" {
                        guard !value.isEmpty, value.utf8.count <= 4096,
                              !value.hasPrefix("-"),
                              !value.contains("%"), !value.contains("$"),
                              !value.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else {
                            throw ParseError.invalidValue("-i")
                        }
                    }
                    break
                }
                if !booleanFlags.contains(letter) {
                    throw ParseError.unknownOption("-\(letter)")
                }
            }

            index += consumedValue ? 2 : 1
        }
    }

    /// Checks the `Keyword=value` payload of a `-o` option.
    private static func validateKeywordOption(_ value: String) throws {
        let parts = value.split(whereSeparator: { $0 == "=" || $0.isWhitespace }).map(String.init)
        guard let first = parts.first else { throw ParseError.missingValue("-o") }
        let keyword = first.lowercased()
        // Dangerous and reserved are named explicitly so the person gets a
        // precise reason for the refusal. Anything else has to be on the allow
        // list, or it is refused: the list, not this pair of sets, is what keeps
        // an unvetted ssh keyword from reaching the command line.
        if dangerousKeywords.contains(keyword) {
            throw ParseError.dangerousOption("-o \(keyword)")
        }
        if reservedKeywords.contains(keyword) {
            throw ParseError.reservedOption("-o \(keyword)")
        }
        guard allowedKeywords.contains(keyword) else {
            throw ParseError.unsupportedKeyword("-o \(keyword)")
        }
        guard parts.count == 2 else { throw ParseError.invalidValue("-o \(keyword)") }
        let argument = parts[1].lowercased()
        let valid: Bool
        switch keyword {
        case "serveraliveinterval": valid = Int(argument).map { (0...3600).contains($0) } ?? false
        case "serveralivecountmax": valid = Int(argument).map { (1...10).contains($0) } ?? false
        case "connectionattempts": valid = Int(argument).map { (1...3).contains($0) } ?? false
        case "tcpkeepalive", "identitiesonly": valid = ["yes", "no"].contains(argument)
        case "addressfamily": valid = ["any", "inet", "inet6"].contains(argument)
        default: valid = false
        }
        guard valid else { throw ParseError.invalidValue("-o \(keyword)") }
    }
}
