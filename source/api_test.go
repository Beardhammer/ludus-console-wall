package main

import (
	"image"
	"image/color"
	"testing"
)

func TestScaleToWidth(t *testing.T) {
	source := image.NewRGBA(image.Rect(0, 0, 1000, 500))
	source.SetRGBA(0, 0, color.RGBA{R: 20, G: 40, B: 60, A: 255})
	got := scaleToWidth(source, 500)
	if got.Bounds().Dx() != 500 || got.Bounds().Dy() != 250 {
		t.Fatalf("scaled bounds = %v, want 500x250", got.Bounds())
	}
	if got.RGBAAt(0, 0) != source.RGBAAt(0, 0) {
		t.Fatal("scaling changed the first pixel")
	}
}

func TestScaleLeavesSmallFramesAlone(t *testing.T) {
	source := image.NewRGBA(image.Rect(0, 0, 320, 200))
	if got := scaleToWidth(source, 640); got != source {
		t.Fatal("small frame was unnecessarily copied")
	}
}

func TestEncodeScreenshot(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 16, 9))
	data, err := encodeScreenshot(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 || string(data[1:4]) != "PNG" {
		t.Fatalf("not a PNG: %x", data[:min(len(data), 8)])
	}
}

func TestEncodeBridgeFrameCapsPayload(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 1800, 1200))
	for i := range frame.Pix {
		frame.Pix[i] = byte((i*73 + i/19) % 251)
	}
	resized, data, err := encodeBridgeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 5<<20 || resized.Bounds().Dx() > 1800 {
		t.Fatalf("frame width=%d bytes=%d", resized.Bounds().Dx(), len(data))
	}
}

func TestValidateInputRequest(t *testing.T) {
	valid := wallInputRequest{VMID: 101, Actions: []wallInputAction{{Type: "key", Keys: []string{"ctrl", "alt", "delete"}}, {Type: "type", Text: "hello"}, {Type: "click", X: 10, Y: 20}}}
	if err := validateInputRequest(valid); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	invalid := wallInputRequest{VMID: 101, Actions: []wallInputAction{{Type: "key", Keys: []string{"not-a-key"}}}}
	if err := validateInputRequest(invalid); err == nil {
		t.Fatal("unknown key was accepted")
	}
}

func TestIsKasmVM(t *testing.T) {
	for _, test := range []struct {
		name, template string
		want           bool
	}{
		{name: "1-kali", want: true},
		{name: "attackbox", template: "kali-x64-server-template", want: true},
		{name: "ubuntu", template: "ubuntu-24.04-x64-server-template", want: false},
	} {
		if got := isKasmVM(test.name, test.template); got != test.want {
			t.Errorf("isKasmVM(%q, %q) = %v, want %v", test.name, test.template, got, test.want)
		}
	}
}

func TestKasmAddressRestrictedToRange(t *testing.T) {
	if !validWallRangeIP("10.42.10.7", 42) {
		t.Fatal("valid range address rejected")
	}
	for _, address := range []string{"127.0.0.1", "169.254.169.254", "10.43.10.7", "not-an-ip"} {
		if validWallRangeIP(address, 42) {
			t.Fatalf("unsafe Kasm address accepted: %s", address)
		}
	}
}
