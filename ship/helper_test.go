package ship

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJsonFromEEBUSJson(t *testing.T) {
	jsonTest := `{"datagram":[{"header":[{"specificationVersion":"1.2.0"},{"addressSource":[{"device":"d:_i:3210_EVSE"},{"entity":[1,1]},{"feature":6}]},{"addressDestination":[{"device":"d:_i:3210_HEMS"},{"entity":[1]},{"feature":1}]},{"msgCounter":194},{"msgCounterReference":4890},{"cmdClassifier":"reply"}]},{"payload":[{"cmd":[[{"deviceClassificationManufacturerData":[{"deviceName":""},{"deviceCode":""},{"brandName":""},{"powerSource":"mains3Phase"}]}]]}]}]}`
	jsonExpected := `{"datagram":{"header":{"specificationVersion":"1.2.0","addressSource":{"device":"d:_i:3210_EVSE","entity":[1,1],"feature":6},"addressDestination":{"device":"d:_i:3210_HEMS","entity":[1],"feature":1},"msgCounter":194,"msgCounterReference":4890,"cmdClassifier":"reply"},"payload":{"cmd":[{"deviceClassificationManufacturerData":{"deviceName":"","deviceCode":"","brandName":"","powerSource":"mains3Phase"}}]}}}`

	var json = JsonFromEEBUSJson([]byte(jsonTest))

	if string(json) != jsonExpected {
		t.Errorf("\nExpected:\n  %s\ngot:\n  %s", jsonExpected, json)
	}
}

// The PMCP device mistakenly adds an `0x00` byte at the end of many messages. Test if this is handled correctly
func TestJsonFromEEBUSJsonTrailingZeros(t *testing.T) {
	bytes := []byte(`{"datagram":[{"header":[{"specificationVersion":"1.2.0"},{"addressSource":[{"device":"d:_i:3210_EVSE"},{"entity":[1,1]},{"feature":6}]},{"addressDestination":[{"device":"d:_i:3210_HEMS"},{"entity":[1]},{"feature":1}]},{"msgCounter":194},{"msgCounterReference":4890},{"cmdClassifier":"reply"}]},{"payload":[{"cmd":[[{"deviceClassificationManufacturerData":[{"deviceName":""},{"deviceCode":""},{"brandName":""},{"powerSource":"mains3Phase"}]}]]}]}]}`)
	bytes = append(bytes, 0x00)

	jsonTest := string(bytes[:])
	jsonExpected := `{"datagram":{"header":{"specificationVersion":"1.2.0","addressSource":{"device":"d:_i:3210_EVSE","entity":[1,1],"feature":6},"addressDestination":{"device":"d:_i:3210_HEMS","entity":[1],"feature":1},"msgCounter":194,"msgCounterReference":4890,"cmdClassifier":"reply"},"payload":{"cmd":[{"deviceClassificationManufacturerData":{"deviceName":"","deviceCode":"","brandName":"","powerSource":"mains3Phase"}}]}}}`

	var json = JsonFromEEBUSJson([]byte(jsonTest))

	if string(json) != jsonExpected {
		t.Errorf("\nExpected:\n  %s\ngot:\n  %s", jsonExpected, json)
	}
}

// TC_SHIP_MSG_003 (issue #97): the DUT must parse SHIP messages containing
// structural whitespace (Space 0x20, Tab 0x09, LF 0x0A, CR 0x0D) before or
// after the structural characters { } [ ] : , as permitted by RFC 8259 §2, and
// process them identically to the compact equivalent.
func TestJsonFromEEBUSJsonWhitespace(t *testing.T) {
	// All fragments must convert to this same compact object.
	expected := `{"a":1,"b":2}`

	tests := []struct {
		name string
		in   string
	}{
		{"compact", `[{"a":1},{"b":2}]`},
		{"spaces around outer brackets", `[ {"a":1},{"b":2} ]`},
		{"space after comma between objects", `[{"a":1}, {"b":2}]`},
		{"space before comma between objects", `[{"a":1} ,{"b":2}]`},
		{"spaces around comma between objects", `[{"a":1} , {"b":2}]`},
		{"spaces around colons", `[{"a" : 1},{"b" : 2}]`},
		{"tabs", "[\t{\"a\":1},\t{\"b\":2}\t]"},
		{"newlines", "[\n{\"a\":1},\n{\"b\":2}\n]"},
		{"carriage returns", "[\r{\"a\":1},\r{\"b\":2}\r]"},
		{"mixed whitespace everywhere", " [ \t{\r\n\"a\" : 1 } ,\n { \"b\":2 } ] \n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(JsonFromEEBUSJson([]byte(tt.in)))
			if got != expected {
				t.Errorf("\nInput:\n  %q\nExpected:\n  %s\ngot:\n  %s", tt.in, expected, got)
			}
		})
	}
}

// Whitespace inside string values must be preserved (json.Compact only removes
// insignificant whitespace, never whitespace within a string).
func TestJsonFromEEBUSJsonWhitespaceInsideStrings(t *testing.T) {
	in := `[ {"note":"hello   world"} , {"tabbed":"a\tb"} ]`
	expected := `{"note":"hello   world","tabbed":"a\tb"}`

	got := string(JsonFromEEBUSJson([]byte(in)))
	if got != expected {
		t.Errorf("\nExpected:\n  %s\ngot:\n  %s", expected, got)
	}
}

// A pretty-printed real datagram (indented with json.Indent, which inserts LF +
// tab indentation and a space after every ':') must convert identically to the
// compact form.
func TestJsonFromEEBUSJsonIndented(t *testing.T) {
	compact := `{"datagram":[{"header":[{"specificationVersion":"1.2.0"},{"addressSource":[{"device":"d:_i:3210_EVSE"},{"entity":[1,1]},{"feature":6}]},{"addressDestination":[{"device":"d:_i:3210_HEMS"},{"entity":[1]},{"feature":1}]},{"msgCounter":194},{"msgCounterReference":4890},{"cmdClassifier":"reply"}]},{"payload":[{"cmd":[[{"deviceClassificationManufacturerData":[{"deviceName":""},{"deviceCode":""},{"brandName":""},{"powerSource":"mains3Phase"}]}]]}]}]}`
	expected := `{"datagram":{"header":{"specificationVersion":"1.2.0","addressSource":{"device":"d:_i:3210_EVSE","entity":[1,1],"feature":6},"addressDestination":{"device":"d:_i:3210_HEMS","entity":[1],"feature":1},"msgCounter":194,"msgCounterReference":4890,"cmdClassifier":"reply"},"payload":{"cmd":[{"deviceClassificationManufacturerData":{"deviceName":"","deviceCode":"","brandName":"","powerSource":"mains3Phase"}}]}}}`

	var indented bytes.Buffer
	if err := json.Indent(&indented, []byte(compact), "", "\t"); err != nil {
		t.Fatal(err)
	}

	got := string(JsonFromEEBUSJson(indented.Bytes()))
	if got != expected {
		t.Errorf("\nExpected:\n  %s\ngot:\n  %s", expected, got)
	}
}

func TestJsonIntoEEBUSJson(t *testing.T) {
	jsonTest := `{"datagram":{"header":{"specificationVersion":"1.2.0","addressSource":{"device":"d:_i:3210_EVSE","entity":[1,1],"feature":6},"addressDestination":{"device":"d:_i:3210_HEMS","entity":[1],"feature":1},"msgCounter":194,"msgCounterReference":4890,"cmdClassifier":"reply"},"payload":{"cmd":[{"deviceClassificationManufacturerData":{"deviceName":"","deviceCode":"","brandName":"","powerSource":"mains3Phase"}}]}}}`
	jsonExpected := `{"datagram":[{"header":[{"specificationVersion":"1.2.0"},{"addressSource":[{"device":"d:_i:3210_EVSE"},{"entity":[1,1]},{"feature":6}]},{"addressDestination":[{"device":"d:_i:3210_HEMS"},{"entity":[1]},{"feature":1}]},{"msgCounter":194},{"msgCounterReference":4890},{"cmdClassifier":"reply"}]},{"payload":[{"cmd":[[{"deviceClassificationManufacturerData":[{"deviceName":""},{"deviceCode":""},{"brandName":""},{"powerSource":"mains3Phase"}]}]]}]}]}`

	var json, err = JsonIntoEEBUSJson([]byte(jsonTest))
	if err != nil {
		println(err.Error())
		t.Errorf("\nExpected:\n  %s\ngot:\n  %s", jsonExpected, json)
	}

	if json != jsonExpected {
		t.Errorf("\nExpected:\n  %s\ngot:\n  %s", jsonExpected, json)
	}
}

