import SwiftUI
import XCTest
@testable import SSH_Wakey

/// Pins which columns a person is allowed to switch off. A row that cannot show
/// which machine it is, or who it logs in as, is not worth showing at all.
final class ColumnTests: XCTestCase {

    func testOnlyPortAndExtraArgumentsAreOptional() {
        XCTAssertEqual(Set(Column.optional), [.port, .arguments])
    }

    func testTheIdentifyingColumnsAreRequired() {
        let required = Set(Column.allCases).subtracting(Column.optional)
        XCTAssertEqual(required, [.status, .name, .username, .host, .added, .lastEdited])
    }

    func testEveryColumnHasAStableIdentifierAndATitle() {
        for column in Column.allCases {
            XCTAssertEqual(column.id, column.rawValue)
            XCTAssertFalse(column.title.isEmpty, column.rawValue)
        }
        // Identifiers are persisted in user defaults, so they must not drift.
        XCTAssertEqual(Column.port.id, "port")
        XCTAssertEqual(Column.arguments.id, "arguments")
        XCTAssertEqual(Column.lastEdited.id, "lastEdited")
    }
}

/// The table used to scroll sideways because SwiftUI wrote the width it had just
/// worked out back into the saved layout, which pinned every column. Restored
/// into a smaller window, those pinned widths no longer fitted. These tests hold
/// the two halves of the fix in place: the widths fit by construction, and the
/// saved layout carries no widths at all.
final class ColumnWidthTests: XCTestCase {

    func testEveryColumnCanShrinkOrIsDeliberatelyFixed() {
        for column in Column.allCases {
            XCTAssertLessThanOrEqual(column.minimumWidth, column.idealWidth, column.title)
            XCTAssertGreaterThan(column.minimumWidth, 0, column.title)
        }
        XCTAssertEqual(Set(Column.allCases.filter(\.isFixedWidth)), [.status, .port])
    }

    func testEveryColumnFitsAtItsIdealWidthInTheSmallestWindow() {
        XCTAssertLessThanOrEqual(
            Column.totalIdealWidth + Column.tableChrome, Column.minimumWindowWidth,
            "the narrowest allowed window must still fit every column without scrolling")
    }

    func testTheSmallestWindowIsStillAReasonableSize() {
        XCTAssertGreaterThan(Column.minimumWindowWidth, 600)
        XCTAssertLessThan(Column.minimumWindowWidth, 1000)
    }

    func testHidingTheOptionalColumnsBuysBackRealWidth() {
        let optional = Column.optional.reduce(0) { $0 + $1.idealWidth }
        XCTAssertGreaterThan(optional, 100, "hiding Port and Extra arguments should be worth doing")
    }

    // MARK: - Saved layout

    /// The shape SwiftUI actually encodes: a flat array alternating a column
    /// identifier with its state.
    private let savedLayout = Data("""
    {"perColumnState":[
      {"base":{"explicit":{"_0":"name"}}},
      {"currentWidth":150,"visibility":{"automatic":{}}},
      {"base":{"explicit":{"_0":"port"}}},
      {"visibility":{"hidden":{}}}
    ]}
    """.utf8)

    func testSavingTheLayoutDropsTheWidths() throws {
        let stripped = try XCTUnwrap(ContentView.strippingWidths(from: savedLayout))
        let text = String(decoding: stripped, as: UTF8.self)
        XCTAssertFalse(text.contains("currentWidth"), text)
    }

    func testSavingTheLayoutKeepsWhichColumnsShowAndInWhatOrder() throws {
        let stripped = try XCTUnwrap(ContentView.strippingWidths(from: savedLayout))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: stripped) as? [String: Any])
        let states = try XCTUnwrap(object["perColumnState"] as? [Any])

        XCTAssertEqual(states.count, 4, "identifiers and states must both survive")
        let text = String(decoding: stripped, as: UTF8.self)
        XCTAssertTrue(text.contains("name"))
        XCTAssertTrue(text.contains("port"))
        XCTAssertTrue(text.contains("hidden"))
        XCTAssertTrue(text.contains("visibility"))
    }

    /// The half that matters most: what the app writes, the app must be able to
    /// read back.
    func testAStrippedLayoutStillLoads() throws {
        let stripped = try XCTUnwrap(ContentView.strippingWidths(from: savedLayout))
        let restored = try JSONDecoder().decode(
            TableColumnCustomization<SSHConnection>.self, from: stripped)

        XCTAssertEqual(restored[visibility: Column.port.id], .hidden,
                       "a hidden column must still come back hidden")
        XCTAssertNotEqual(restored[visibility: Column.name.id], .hidden)
    }

    func testNonsenseIsRejectedRatherThanCorrupted() {
        XCTAssertNil(ContentView.strippingWidths(from: Data("not json".utf8)))
        XCTAssertNil(ContentView.strippingWidths(from: Data("{}".utf8)))
    }
}
