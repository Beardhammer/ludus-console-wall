// Package rfb implements the small subset of RFB 3.8 needed by Console Wall.
// It supports raw screenshots plus keyboard and pointer input while keeping
// the protocol implementation deterministic and dependency-free.
package rfb

import (
	"bufio"
	"context"
	"crypto/des" //nolint:gosec -- VNC authentication mandates DES
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"io"
	"strings"
	"time"
)

var (
	ErrProtocol            = errors.New("rfb: protocol error")
	ErrAuthFailed          = errors.New("rfb: authentication failed")
	ErrClosed              = errors.New("rfb: server closed the connection")
	ErrUnsupportedEncoding = errors.New("rfb: unsupported encoding")
)

const (
	protocolVersion = "RFB 003.008\n"
	securityNone    = 1
	securityVNC     = 2
	encodingRaw     = int32(0)
	encodingDesktop = int32(-223)
	maxDimension    = 8192
	maxString       = 1 << 20
)

type Conn interface {
	io.ReadWriter
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type Options struct {
	Password     string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	KeyDelay     time.Duration
	MouseDelay   time.Duration
}

type Client struct {
	conn          Conn
	reader        *bufio.Reader
	options       Options
	width, height int
	heldKeys      map[uint32]int
	buttonMask    uint8
	pointerX      int
	pointerY      int
}

func New(conn Conn, options Options) *Client {
	if options.ReadTimeout == 0 {
		options.ReadTimeout = 20 * time.Second
	}
	if options.WriteTimeout == 0 {
		options.WriteTimeout = 5 * time.Second
	}
	if options.KeyDelay == 0 {
		options.KeyDelay = 10 * time.Millisecond
	}
	if options.MouseDelay == 0 {
		options.MouseDelay = 60 * time.Millisecond
	}
	return &Client{conn: conn, reader: bufio.NewReaderSize(conn, 64*1024), options: options, heldKeys: map[uint32]int{}}
}

func (c *Client) Width() int  { return c.width }
func (c *Client) Height() int { return c.height }

func deadline(ctx context.Context, timeout time.Duration) time.Time {
	value := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(value) {
		return contextDeadline
	}
	return value
}

func (c *Client) read(ctx context.Context, target []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.conn.SetReadDeadline(deadline(ctx, c.options.ReadTimeout)); err != nil {
		return err
	}
	if _, err := io.ReadFull(c.reader, target); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: %v", ErrClosed, err)
		}
		return err
	}
	return nil
}

func (c *Client) write(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.conn.SetWriteDeadline(deadline(ctx, c.options.WriteTimeout)); err != nil {
		return err
	}
	_, err := c.conn.Write(data)
	return err
}

func (c *Client) discard(ctx context.Context, count int64) error {
	if err := c.conn.SetReadDeadline(deadline(ctx, c.options.ReadTimeout)); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, c.reader, count)
	return err
}

func (c *Client) Handshake(ctx context.Context) error {
	version := make([]byte, 12)
	if err := c.read(ctx, version); err != nil {
		return fmt.Errorf("read protocol version: %w", err)
	}
	if string(version) != protocolVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrProtocol, version)
	}
	if err := c.write(ctx, []byte(protocolVersion)); err != nil {
		return err
	}
	if err := c.security(ctx); err != nil {
		return err
	}
	if err := c.write(ctx, []byte{1}); err != nil {
		return err
	}
	header := make([]byte, 20)
	if err := c.read(ctx, header); err != nil {
		return fmt.Errorf("read ServerInit: %w", err)
	}
	c.width, c.height = int(binary.BigEndian.Uint16(header[:2])), int(binary.BigEndian.Uint16(header[2:4]))
	if err := c.checkDimensions(c.width, c.height); err != nil {
		return err
	}
	if _, err := c.readString(ctx); err != nil {
		return err
	}
	if err := c.setPixelFormat(ctx); err != nil {
		return err
	}
	return c.setEncodings(ctx)
}

func (c *Client) security(ctx context.Context) error {
	count := []byte{0}
	if err := c.read(ctx, count); err != nil {
		return err
	}
	if count[0] == 0 {
		reason, _ := c.readString(ctx)
		return fmt.Errorf("%w: server refused connection: %s", ErrProtocol, reason)
	}
	types := make([]byte, int(count[0]))
	if err := c.read(ctx, types); err != nil {
		return err
	}
	chosen := byte(0)
	for _, value := range types {
		if value == securityVNC {
			chosen = securityVNC
			break
		}
		if value == securityNone {
			chosen = securityNone
		}
	}
	if chosen == 0 {
		return fmt.Errorf("%w: unsupported security types %v", ErrProtocol, types)
	}
	if err := c.write(ctx, []byte{chosen}); err != nil {
		return err
	}
	if chosen == securityVNC {
		challenge := make([]byte, 16)
		if err := c.read(ctx, challenge); err != nil {
			return err
		}
		response, err := vncResponse(challenge, c.options.Password)
		if err != nil {
			return err
		}
		if err := c.write(ctx, response); err != nil {
			return err
		}
	}
	result := make([]byte, 4)
	if err := c.read(ctx, result); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(result) != 0 {
		reason, _ := c.readString(ctx)
		return fmt.Errorf("%w: %s", ErrAuthFailed, reason)
	}
	return nil
}

func vncResponse(challenge []byte, password string) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("%w: invalid VNC challenge", ErrProtocol)
	}
	key := make([]byte, 8)
	copy(key, []byte(password))
	for i, value := range key {
		value = (value&0xf0)>>4 | (value&0x0f)<<4
		value = (value&0xcc)>>2 | (value&0x33)<<2
		key[i] = (value&0xaa)>>1 | (value&0x55)<<1
	}
	block, err := des.NewCipher(key) //nolint:gosec -- VNC protocol requirement
	if err != nil {
		return nil, err
	}
	response := make([]byte, 16)
	block.Encrypt(response[:8], challenge[:8])
	block.Encrypt(response[8:], challenge[8:])
	return response, nil
}

func (c *Client) readString(ctx context.Context) (string, error) {
	lengthBytes := make([]byte, 4)
	if err := c.read(ctx, lengthBytes); err != nil {
		return "", err
	}
	length := binary.BigEndian.Uint32(lengthBytes)
	if length > maxString {
		return "", fmt.Errorf("%w: string is too large", ErrProtocol)
	}
	value := make([]byte, int(length))
	if err := c.read(ctx, value); err != nil {
		return "", err
	}
	return string(value), nil
}

func (c *Client) checkDimensions(width, height int) error {
	if width <= 0 || height <= 0 || width > maxDimension || height > maxDimension {
		return fmt.Errorf("%w: invalid framebuffer %dx%d", ErrProtocol, width, height)
	}
	return nil
}

func (c *Client) setPixelFormat(ctx context.Context) error {
	return c.write(ctx, []byte{0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0})
}

func (c *Client) setEncodings(ctx context.Context) error {
	message := make([]byte, 12)
	message[0] = 2
	binary.BigEndian.PutUint16(message[2:4], 2)
	binary.BigEndian.PutUint32(message[4:8], uint32(encodingRaw))
	desktopEncoding := encodingDesktop
	binary.BigEndian.PutUint32(message[8:12], uint32(desktopEncoding))
	return c.write(ctx, message)
}

func (c *Client) Screenshot(ctx context.Context) (*image.RGBA, error) {
	for attempt := 0; attempt < 3; attempt++ {
		request := make([]byte, 10)
		request[0] = 3
		binary.BigEndian.PutUint16(request[6:8], uint16(c.width))
		binary.BigEndian.PutUint16(request[8:10], uint16(c.height))
		if err := c.write(ctx, request); err != nil {
			return nil, err
		}
		frame, resized, err := c.readUpdate(ctx)
		if err != nil {
			return nil, err
		}
		if !resized {
			return frame, nil
		}
	}
	return nil, fmt.Errorf("%w: framebuffer kept resizing", ErrProtocol)
}

func (c *Client) readUpdate(ctx context.Context) (*image.RGBA, bool, error) {
	for {
		messageType := []byte{0}
		if err := c.read(ctx, messageType); err != nil {
			return nil, false, err
		}
		switch messageType[0] {
		case 0:
			return c.readRectangles(ctx)
		case 1:
			header := make([]byte, 5)
			if err := c.read(ctx, header); err != nil {
				return nil, false, err
			}
			if err := c.discard(ctx, int64(binary.BigEndian.Uint16(header[3:5]))*6); err != nil {
				return nil, false, err
			}
		case 2:
			// bell, no payload
		case 3:
			header := make([]byte, 7)
			if err := c.read(ctx, header); err != nil {
				return nil, false, err
			}
			length := binary.BigEndian.Uint32(header[3:])
			if length > maxString {
				return nil, false, fmt.Errorf("%w: clipboard is too large", ErrProtocol)
			}
			if err := c.discard(ctx, int64(length)); err != nil {
				return nil, false, err
			}
		default:
			return nil, false, fmt.Errorf("%w: unknown message %d", ErrProtocol, messageType[0])
		}
	}
}

func (c *Client) readRectangles(ctx context.Context) (*image.RGBA, bool, error) {
	header := make([]byte, 3)
	if err := c.read(ctx, header); err != nil {
		return nil, false, err
	}
	count := int(binary.BigEndian.Uint16(header[1:]))
	frame := image.NewRGBA(image.Rect(0, 0, c.width, c.height))
	resized, covered := false, 0
	for i := 0; i < count; i++ {
		rectangle := make([]byte, 12)
		if err := c.read(ctx, rectangle); err != nil {
			return nil, false, err
		}
		x, y := int(binary.BigEndian.Uint16(rectangle[:2])), int(binary.BigEndian.Uint16(rectangle[2:4]))
		width, height := int(binary.BigEndian.Uint16(rectangle[4:6])), int(binary.BigEndian.Uint16(rectangle[6:8]))
		encoding := int32(binary.BigEndian.Uint32(rectangle[8:]))
		switch encoding {
		case encodingDesktop:
			if err := c.checkDimensions(width, height); err != nil {
				return nil, false, err
			}
			if width != c.width || height != c.height {
				c.width, c.height = width, height
				frame = image.NewRGBA(image.Rect(0, 0, width, height))
				resized, covered = true, 0
			}
		case encodingRaw:
			if x+width > c.width || y+height > c.height {
				return nil, false, fmt.Errorf("%w: rectangle outside framebuffer", ErrProtocol)
			}
			line := make([]byte, width*4)
			for row := 0; row < height; row++ {
				if err := c.read(ctx, line); err != nil {
					return nil, false, err
				}
				offset := frame.PixOffset(x, y+row)
				for column := 0; column < width; column++ {
					source, target := column*4, offset+column*4
					frame.Pix[target], frame.Pix[target+1], frame.Pix[target+2], frame.Pix[target+3] = line[source+2], line[source+1], line[source], 255
				}
			}
			covered += width * height
		default:
			return nil, false, fmt.Errorf("%w: %d", ErrUnsupportedEncoding, encoding)
		}
	}
	return frame, resized && covered < c.width*c.height, nil
}

type Button uint8

const (
	ButtonLeft   Button = 1 << 0
	ButtonMiddle Button = 1 << 1
	ButtonRight  Button = 1 << 2

	keyBackspace = uint32(0xff08)
	keyTab       = uint32(0xff09)
	keyEnter     = uint32(0xff0d)
	keyEscape    = uint32(0xff1b)
	keyHome      = uint32(0xff50)
	keyLeft      = uint32(0xff51)
	keyUp        = uint32(0xff52)
	keyRight     = uint32(0xff53)
	keyDown      = uint32(0xff54)
	keyPageUp    = uint32(0xff55)
	keyPageDown  = uint32(0xff56)
	keyEnd       = uint32(0xff57)
	keyInsert    = uint32(0xff63)
	keyF1        = uint32(0xffbe)
	keyShift     = uint32(0xffe1)
	keyControl   = uint32(0xffe3)
	keyAlt       = uint32(0xffe9)
	keySuper     = uint32(0xffeb)
	keyDelete    = uint32(0xffff)
)

var namedKeys = map[string]uint32{
	"ctrl": keyControl, "control": keyControl, "alt": keyAlt, "shift": keyShift,
	"win": keySuper, "windows": keySuper, "super": keySuper, "cmd": keySuper,
	"enter": keyEnter, "return": keyEnter, "tab": keyTab, "esc": keyEscape, "escape": keyEscape,
	"backspace": keyBackspace, "delete": keyDelete, "del": keyDelete, "insert": keyInsert,
	"home": keyHome, "end": keyEnd, "pgup": keyPageUp, "pageup": keyPageUp,
	"pgdn": keyPageDown, "pagedown": keyPageDown, "up": keyUp, "down": keyDown,
	"left": keyLeft, "right": keyRight, "space": ' ', "minus": '-', "plus": '+',
}

var modifiers = map[uint32]bool{keyControl: true, keyAlt: true, keyShift: true, keySuper: true}

var shiftedCharacters = map[rune]rune{
	'1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
	'-': '_', '=': '+', '[': '{', ']': '}', '\\': '|', ';': ':', '\'': '"', ',': '<', '.': '>', '/': '?', '`': '~',
}

func init() {
	for i := 0; i < 12; i++ {
		namedKeys[fmt.Sprintf("f%d", i+1)] = keyF1 + uint32(i)
	}
}

func keyForName(name string) (uint32, bool, bool) {
	if key, ok := namedKeys[strings.ToLower(name)]; ok {
		return key, false, true
	}
	runes := []rune(name)
	if len(runes) != 1 {
		return 0, false, false
	}
	key, shift := keyForRune(runes[0])
	return key, shift, true
}

func keyForRune(value rune) (uint32, bool) {
	if value == '\n' || value == '\r' {
		return keyEnter, false
	}
	if value == '\t' {
		return keyTab, false
	}
	if value >= 'A' && value <= 'Z' {
		return uint32(value + ('a' - 'A')), true
	}
	for base, shifted := range shiftedCharacters {
		if shifted == value {
			return uint32(base), true
		}
	}
	if value >= 0x20 && value <= 0xff {
		return uint32(value), false
	}
	return 0x01000000 + uint32(value), false
}

func ParseChordKeys(names []string) ([]uint32, uint32, error) {
	if len(names) == 0 {
		return nil, 0, fmt.Errorf("at least one key is required")
	}
	mods := make([]uint32, 0, len(names)-1)
	for _, name := range names[:len(names)-1] {
		key, _, ok := keyForName(name)
		if !ok {
			return nil, 0, fmt.Errorf("unknown key %q", name)
		}
		if !modifiers[key] {
			return nil, 0, fmt.Errorf("%q is not a modifier", name)
		}
		mods = append(mods, key)
	}
	key, shift, ok := keyForName(names[len(names)-1])
	if !ok {
		return nil, 0, fmt.Errorf("unknown key %q", names[len(names)-1])
	}
	if shift {
		containsShift := false
		for _, modifier := range mods {
			containsShift = containsShift || modifier == keyShift
		}
		if !containsShift {
			mods = append(mods, keyShift)
		}
	}
	return mods, key, nil
}

func (c *Client) keyEvent(ctx context.Context, key uint32, down bool) error {
	message := make([]byte, 8)
	message[0] = 4
	if down {
		message[1] = 1
	}
	binary.BigEndian.PutUint32(message[4:], key)
	return c.write(ctx, message)
}

func (c *Client) keyDown(ctx context.Context, key uint32) error {
	if err := c.keyEvent(ctx, key, true); err != nil {
		return err
	}
	c.heldKeys[key]++
	return nil
}

func (c *Client) keyUp(ctx context.Context, key uint32) error {
	if err := c.keyEvent(ctx, key, false); err != nil {
		return err
	}
	if c.heldKeys[key] > 1 {
		c.heldKeys[key]--
	} else {
		delete(c.heldKeys, key)
	}
	return nil
}

func (c *Client) tap(ctx context.Context, key uint32) error {
	if err := c.keyDown(ctx, key); err != nil {
		return err
	}
	time.Sleep(c.options.KeyDelay)
	return c.keyUp(ctx, key)
}

func (c *Client) SendChord(ctx context.Context, mods []uint32, key uint32) error {
	pressed := make([]uint32, 0, len(mods))
	for _, modifier := range mods {
		if c.heldKeys[modifier] > 0 {
			continue
		}
		if err := c.keyDown(ctx, modifier); err != nil {
			return err
		}
		pressed = append(pressed, modifier)
	}
	err := c.tap(ctx, key)
	for i := len(pressed) - 1; i >= 0; i-- {
		if releaseErr := c.keyUp(ctx, pressed[i]); err == nil && releaseErr != nil {
			err = releaseErr
		}
	}
	return err
}

func (c *Client) Type(ctx context.Context, text string) error {
	for _, value := range text {
		key, shift := keyForRune(value)
		if shift {
			if err := c.SendChord(ctx, []uint32{keyShift}, key); err != nil {
				return err
			}
		} else if err := c.tap(ctx, key); err != nil {
			return err
		}
		time.Sleep(c.options.KeyDelay)
	}
	return nil
}

// SetKeyState preserves held modifiers and keys across interactive requests.
func (c *Client) SetKeyState(ctx context.Context, name string, down bool) error {
	key, _, ok := keyForName(name)
	if !ok {
		return fmt.Errorf("unknown key %q", name)
	}
	if down {
		if c.heldKeys[key] > 0 {
			return nil
		}
		return c.keyDown(ctx, key)
	}
	if c.heldKeys[key] == 0 {
		return nil
	}
	return c.keyUp(ctx, key)
}

func (c *Client) pointerEvent(ctx context.Context) error {
	message := make([]byte, 6)
	message[0] = 5
	message[1] = c.buttonMask
	binary.BigEndian.PutUint16(message[2:4], uint16(c.pointerX))
	binary.BigEndian.PutUint16(message[4:6], uint16(c.pointerY))
	return c.write(ctx, message)
}

func (c *Client) MoveTo(ctx context.Context, x, y int) error {
	if x < 0 || y < 0 || x >= c.width || y >= c.height {
		return fmt.Errorf("%w: %d,%d outside %dx%d", ErrProtocol, x, y, c.width, c.height)
	}
	c.pointerX, c.pointerY = x, y
	if err := c.pointerEvent(ctx); err != nil {
		return err
	}
	time.Sleep(c.options.MouseDelay)
	return nil
}

func (c *Client) Click(ctx context.Context, button Button, count int) error {
	for i := 0; i < count; i++ {
		c.buttonMask |= uint8(button)
		if err := c.pointerEvent(ctx); err != nil {
			return err
		}
		time.Sleep(c.options.KeyDelay)
		c.buttonMask &^= uint8(button)
		if err := c.pointerEvent(ctx); err != nil {
			return err
		}
		if i+1 < count {
			time.Sleep(80 * time.Millisecond)
		}
	}
	return nil
}

// SetPointerState supports mouse drag without releasing between RPC calls.
func (c *Client) SetPointerState(ctx context.Context, x, y int, button Button, down bool) error {
	if x < 0 || y < 0 || x >= c.width || y >= c.height {
		return fmt.Errorf("%w: %d,%d outside %dx%d", ErrProtocol, x, y, c.width, c.height)
	}
	c.pointerX, c.pointerY = x, y
	if button != 0 {
		if down {
			c.buttonMask |= uint8(button)
		} else {
			c.buttonMask &^= uint8(button)
		}
	}
	return c.pointerEvent(ctx)
}

// Scroll sends RFB wheel button pulses while retaining held mouse buttons.
func (c *Client) Scroll(ctx context.Context, x, y, deltaX, deltaY int) error {
	if err := c.SetPointerState(ctx, x, y, 0, false); err != nil {
		return err
	}
	for _, axis := range []struct {
		delta              int
		negative, positive uint8
	}{{deltaY, 8, 16}, {deltaX, 32, 64}} {
		count := axis.delta
		bit := axis.positive
		if count < 0 {
			count = -count
			bit = axis.negative
		}
		if count > 5 {
			count = 5
		}
		for i := 0; i < count; i++ {
			c.buttonMask |= bit
			if err := c.pointerEvent(ctx); err != nil {
				return err
			}
			c.buttonMask &^= bit
			if err := c.pointerEvent(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) ReleaseAll(ctx context.Context) error {
	var first error
	for key := range c.heldKeys {
		if err := c.keyEvent(ctx, key, false); err != nil && first == nil {
			first = err
		}
	}
	c.heldKeys = map[uint32]int{}
	if c.buttonMask != 0 {
		c.buttonMask = 0
		if err := c.pointerEvent(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}
