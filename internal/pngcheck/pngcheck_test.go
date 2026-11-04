package pngcheck

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func realPNG(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.NRGBA{uint8(x * 7), uint8(y * 5), 90, 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func chunk(typ string, body []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(body)))
	b.WriteString(typ)
	b.Write(body)
	binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), body...)))
	return b.Bytes()
}

func ihdr(w, h uint32, depth, ct byte) []byte {
	body := make([]byte, 13)
	binary.BigEndian.PutUint32(body, w)
	binary.BigEndian.PutUint32(body[4:], h)
	body[8], body[9] = depth, ct
	return chunk("IHDR", body)
}

// minimal assembles a structurally valid PNG whose pixel data is never decoded.
func minimal(w, h uint32, extra ...[]byte) []byte {
	var b bytes.Buffer
	b.Write(signature)
	b.Write(ihdr(w, h, 8, 6))
	for _, e := range extra {
		b.Write(e)
	}
	b.Write(chunk("IDAT", []byte{0x78, 0x9c, 0, 0}))
	b.Write(chunk("IEND", nil))
	return b.Bytes()
}

func TestAcceptsRealPNG(t *testing.T) {
	in := realPNG(t, 40, 30)
	out, info, err := Sanitize(in, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if info.Width != 40 || info.Height != 30 {
		t.Fatalf("info %+v", info)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil || img.Bounds().Dx() != 40 {
		t.Fatalf("output is not a decodable PNG: %v", err)
	}
}

func TestStripsMetadata(t *testing.T) {
	secret := []byte("author=jane gps=1.23")
	in := minimal(10, 10,
		chunk("tEXt", append([]byte("Comment\x00"), secret...)),
		chunk("eXIf", secret),
		chunk("iTXt", secret),
		chunk("tIME", make([]byte, 7)),
		chunk("zZZz", secret), // private ancillary
		chunk("pHYs", make([]byte, 9)),
	)
	out, _, err := Sanitize(in, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, secret) {
		t.Fatal("metadata survived")
	}
	for _, name := range []string{"tEXt", "eXIf", "iTXt", "tIME", "zZZz"} {
		if bytes.Contains(out, []byte(name)) {
			t.Fatalf("%s survived", name)
		}
	}
	if !bytes.Contains(out, []byte("pHYs")) {
		t.Fatal("pHYs dropped")
	}
	if _, _, err := Sanitize(out, DefaultLimits); err != nil {
		t.Fatalf("output not re-accepted: %v", err)
	}
}

func TestRejects(t *testing.T) {
	good := minimal(10, 10)
	corruptCRC := append([]byte(nil), good...)
	corruptCRC[len(signature)+8] ^= 0xff // flip a bit in IHDR body

	noIEND := good[:len(good)-12]
	trailing := append(append([]byte(nil), good...), 0)
	afterIEND := append(append([]byte(nil), good...), chunk("tEXt", []byte("a\x00b"))...)

	var splitIDAT bytes.Buffer
	splitIDAT.Write(signature)
	splitIDAT.Write(ihdr(4, 4, 8, 6))
	splitIDAT.Write(chunk("IDAT", []byte{0x78, 0x9c}))
	splitIDAT.Write(chunk("tEXt", []byte("a\x00b")))
	splitIDAT.Write(chunk("IDAT", []byte{1, 2}))
	splitIDAT.Write(chunk("IEND", nil))

	var noIDAT bytes.Buffer
	noIDAT.Write(signature)
	noIDAT.Write(ihdr(4, 4, 8, 6))
	noIDAT.Write(chunk("IEND", nil))

	var noIHDRFirst bytes.Buffer
	noIHDRFirst.Write(signature)
	noIHDRFirst.Write(chunk("tEXt", []byte("a\x00b")))
	noIHDRFirst.Write(ihdr(4, 4, 8, 6))
	noIHDRFirst.Write(chunk("IDAT", []byte{0x78, 0x9c}))
	noIHDRFirst.Write(chunk("IEND", nil))

	var badZlib bytes.Buffer
	badZlib.Write(signature)
	badZlib.Write(ihdr(4, 4, 8, 6))
	badZlib.Write(chunk("IDAT", []byte{0, 0, 0}))
	badZlib.Write(chunk("IEND", nil))

	var palNoPLTE bytes.Buffer
	palNoPLTE.Write(signature)
	palNoPLTE.Write(ihdr(4, 4, 8, 3))
	palNoPLTE.Write(chunk("IDAT", []byte{0x78, 0x9c}))
	palNoPLTE.Write(chunk("IEND", nil))

	hugeLen := append([]byte(nil), signature...)
	hugeLen = append(hugeLen, 0xff, 0xff, 0xff, 0xff, 'I', 'H', 'D', 'R')

	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 'J', 'F', 'I', 'F', 0}

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrNotPNG},
		{"jpeg", jpeg, ErrNotPNG},
		{"signature only", signature, ErrCorrupt},
		{"truncated", good[:20], ErrCorrupt},
		{"bad crc", corruptCRC, ErrCorrupt},
		{"no IEND", noIEND, ErrCorrupt},
		{"trailing byte", trailing, ErrCorrupt},
		{"chunk after IEND", afterIEND, ErrCorrupt},
		{"split IDAT", splitIDAT.Bytes(), ErrCorrupt},
		{"no IDAT", noIDAT.Bytes(), ErrCorrupt},
		{"IHDR not first", noIHDRFirst.Bytes(), ErrCorrupt},
		{"bad zlib", badZlib.Bytes(), ErrCorrupt},
		{"palette without PLTE", palNoPLTE.Bytes(), ErrCorrupt},
		{"huge chunk length", hugeLen, ErrCorrupt},
		{"zero width", minimal(0, 10), ErrCorrupt},
		{"side too big", minimal(8193, 10), ErrDimensions},
		{"too many pixels", minimal(8192, 8192), ErrDimensions},
		{"giant", minimal(1<<31-1, 1<<31-1), ErrDimensions},
		{"over int32", minimal(1<<31, 10), ErrCorrupt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Sanitize(c.data, DefaultLimits)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestBadColourTypeDepth(t *testing.T) {
	var b bytes.Buffer
	b.Write(signature)
	b.Write(ihdr(4, 4, 3, 2))
	b.Write(chunk("IDAT", []byte{0x78, 0x9c}))
	b.Write(chunk("IEND", nil))
	if _, _, err := Sanitize(b.Bytes(), DefaultLimits); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

func TestLimitsAreConfigurable(t *testing.T) {
	in := realPNG(t, 50, 50)
	if _, _, err := Sanitize(in, Limits{MaxSide: 49, MaxPixels: 1 << 20}); !errors.Is(err, ErrDimensions) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := Sanitize(in, Limits{MaxSide: 100, MaxPixels: 2499}); !errors.Is(err, ErrDimensions) {
		t.Fatalf("err = %v", err)
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add(realPNG(f, 8, 8))
	f.Add(minimal(3, 3, chunk("tEXt", []byte("k\x00v"))))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, _, err := Sanitize(data, DefaultLimits)
		if err != nil {
			return
		}
		// Anything accepted must be accepted again, unchanged.
		again, _, err := Sanitize(out, DefaultLimits)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("output not stable: %v", err)
		}
	})
}
