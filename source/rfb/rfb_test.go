package rfb

import (
	"bytes"
	"context"
	"testing"
	"time"
)

type eventConn struct{ bytes.Buffer }

func (*eventConn) SetReadDeadline(time.Time) error  { return nil }
func (*eventConn) SetWriteDeadline(time.Time) error { return nil }

func TestParseChordKeys(t *testing.T) {
	mods, key, err := ParseChordKeys([]string{"ctrl", "alt", "delete"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0] != keyControl || mods[1] != keyAlt || key != keyDelete {
		t.Fatalf("unexpected chord: modifiers=%#v key=%#x", mods, key)
	}
}

func TestParseChordAddsShiftForUppercaseAndSymbols(t *testing.T) {
	for _, test := range []struct {
		name string
		key  uint32
	}{
		{name: "A", key: 'a'},
		{name: "!", key: '1'},
	} {
		mods, key, err := ParseChordKeys([]string{test.name})
		if err != nil {
			t.Fatal(err)
		}
		if len(mods) != 1 || mods[0] != keyShift || key != test.key {
			t.Errorf("%q = modifiers %#v key %#x, want shift + %#x", test.name, mods, key, test.key)
		}
	}
}

func TestParseChordRejectsNonModifierPrefix(t *testing.T) {
	if _, _, err := ParseChordKeys([]string{"enter", "a"}); err == nil {
		t.Fatal("non-modifier prefix was accepted")
	}
}

func TestInteractiveHeldKeysAndPointer(t *testing.T) {
	conn := &eventConn{}
	client := New(conn, Options{})
	client.width, client.height = 100, 50
	ctx := context.Background()
	if err := client.SetKeyState(ctx, "ctrl", true); err != nil {
		t.Fatal(err)
	}
	if err := client.SetKeyState(ctx, "ctrl", true); err != nil {
		t.Fatal(err)
	}
	if len(conn.Bytes()) != 8 {
		t.Fatalf("repeat keydown emitted duplicate: %d bytes", len(conn.Bytes()))
	}
	if err := client.SetKeyState(ctx, "ctrl", false); err != nil {
		t.Fatal(err)
	}
	if len(conn.Bytes()) != 16 || client.heldKeys[keyControl] != 0 {
		t.Fatalf("key release failed: %d bytes", len(conn.Bytes()))
	}
	conn.Reset()
	if err := client.SetPointerState(ctx, 10, 20, ButtonLeft, true); err != nil {
		t.Fatal(err)
	}
	if err := client.SetPointerState(ctx, 15, 25, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := client.Scroll(ctx, 15, 25, 0, -1); err != nil {
		t.Fatal(err)
	}
	if err := client.SetPointerState(ctx, 15, 25, ButtonLeft, false); err != nil {
		t.Fatal(err)
	}
	data := conn.Bytes()
	if len(data) != 36 {
		t.Fatalf("pointer bytes=%d", len(data))
	}
	if data[1] != 1 || data[7] != 1 || data[13] != 1 || data[19] != 9 || data[25] != 1 || data[31] != 0 {
		t.Fatalf("pointer masks=%v", []byte{data[1], data[7], data[13], data[19], data[25], data[31]})
	}
}
