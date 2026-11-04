// Package pngcheck validates uploaded PNG files and rewrites them without
// metadata. It never decodes pixel data, so a decompression bomb costs nothing
// here: only the chunk structure, checksums and header are examined.
package pngcheck

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Limits bound what Sanitize accepts.
type Limits struct {
	MaxSide   uint32 // largest allowed width or height, in pixels
	MaxPixels uint64 // largest allowed width*height
}

// DefaultLimits match the largest image DegenView produces (8192 px a side,
// 32 Mi pixels).
var DefaultLimits = Limits{MaxSide: 8192, MaxPixels: 32 << 20}

// Info is what Sanitize learned about the image.
type Info struct {
	Width, Height uint32
}

// Errors returned by Sanitize. Callers map ErrDimensions to "too large" and the
// rest to "not a valid PNG".
var (
	ErrNotPNG     = errors.New("not a PNG file")
	ErrCorrupt    = errors.New("corrupt PNG")
	ErrDimensions = errors.New("image dimensions exceed the limit")
)

var signature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// keep lists the chunks copied to the output. Everything else (tEXt, zTXt,
// iTXt, eXIf, tIME, APNG animation, private chunks) is dropped, so a snapshot
// cannot carry along authoring metadata.
var keep = map[string]bool{
	"IHDR": true, "PLTE": true, "IDAT": true, "IEND": true,
	"tRNS": true, "gAMA": true, "cHRM": true, "sRGB": true,
	"iCCP": true, "sBIT": true, "pHYs": true, "bKGD": true,
}

// validDepths maps colour type to the bit depths the PNG specification allows.
var validDepths = map[byte][]byte{
	0: {1, 2, 4, 8, 16},
	2: {8, 16},
	3: {1, 2, 4, 8},
	4: {8, 16},
	6: {8, 16},
}

// Sanitize validates data as a PNG within lim and returns a copy holding only
// the chunks needed to display it.
func Sanitize(data []byte, lim Limits) ([]byte, Info, error) {
	var info Info
	if len(data) < len(signature) || !bytes.Equal(data[:len(signature)], signature) {
		return nil, info, ErrNotPNG
	}
	out := bytes.NewBuffer(make([]byte, 0, len(data)))
	out.Write(signature)

	pos := len(signature)
	var (
		seenIHDR, seenPLTE, seenIDAT, seenIEND bool
		idatDone                               bool
		colorType                              byte
		first                                  = true
	)
	for pos < len(data) {
		if seenIEND {
			return nil, info, fmt.Errorf("%w: data after IEND", ErrCorrupt)
		}
		if len(data)-pos < 12 {
			return nil, info, fmt.Errorf("%w: truncated chunk header", ErrCorrupt)
		}
		length := binary.BigEndian.Uint32(data[pos:])
		if length > 1<<31-1 || uint64(length)+12 > uint64(len(data)-pos) {
			return nil, info, fmt.Errorf("%w: chunk length", ErrCorrupt)
		}
		typ := data[pos+4 : pos+8]
		for _, c := range typ {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
				return nil, info, fmt.Errorf("%w: chunk type", ErrCorrupt)
			}
		}
		body := data[pos+8 : pos+8+int(length)]
		crc := binary.BigEndian.Uint32(data[pos+8+int(length):])
		if crc32.ChecksumIEEE(data[pos+4:pos+8+int(length)]) != crc {
			return nil, info, fmt.Errorf("%w: checksum", ErrCorrupt)
		}
		name := string(typ)

		if first && name != "IHDR" {
			return nil, info, fmt.Errorf("%w: IHDR must come first", ErrCorrupt)
		}
		first = false

		switch name {
		case "IHDR":
			if seenIHDR || length != 13 {
				return nil, info, fmt.Errorf("%w: IHDR", ErrCorrupt)
			}
			seenIHDR = true
			w := binary.BigEndian.Uint32(body[0:])
			h := binary.BigEndian.Uint32(body[4:])
			depth, ct, comp, filt, ilace := body[8], body[9], body[10], body[11], body[12]
			if w == 0 || h == 0 || w > 1<<31-1 || h > 1<<31-1 {
				return nil, info, fmt.Errorf("%w: zero or negative size", ErrCorrupt)
			}
			if comp != 0 || filt != 0 || ilace > 1 {
				return nil, info, fmt.Errorf("%w: IHDR methods", ErrCorrupt)
			}
			if !depthOK(ct, depth) {
				return nil, info, fmt.Errorf("%w: colour type/bit depth", ErrCorrupt)
			}
			if w > lim.MaxSide || h > lim.MaxSide || uint64(w)*uint64(h) > lim.MaxPixels {
				return nil, info, ErrDimensions
			}
			colorType = ct
			info = Info{Width: w, Height: h}
		case "PLTE":
			if seenPLTE || seenIDAT || length == 0 || length%3 != 0 || length > 3*256 {
				return nil, info, fmt.Errorf("%w: PLTE", ErrCorrupt)
			}
			seenPLTE = true
		case "IDAT":
			if idatDone {
				return nil, info, fmt.Errorf("%w: IDAT chunks are not contiguous", ErrCorrupt)
			}
			if !seenIDAT {
				if length < 2 || !zlibHeaderOK(body[0], body[1]) {
					return nil, info, fmt.Errorf("%w: zlib header", ErrCorrupt)
				}
				if colorType == 3 && !seenPLTE {
					return nil, info, fmt.Errorf("%w: palette image without PLTE", ErrCorrupt)
				}
			}
			seenIDAT = true
		case "IEND":
			if length != 0 || !seenIDAT {
				return nil, info, fmt.Errorf("%w: IEND", ErrCorrupt)
			}
			seenIEND = true
		}
		if seenIDAT && name != "IDAT" {
			idatDone = true
		}

		if keep[name] {
			out.Write(data[pos : pos+12+int(length)])
		}
		pos += 12 + int(length)
	}
	if !seenIHDR || !seenIDAT || !seenIEND {
		return nil, info, fmt.Errorf("%w: missing chunks", ErrCorrupt)
	}
	return out.Bytes(), info, nil
}

func depthOK(colorType, depth byte) bool {
	for _, d := range validDepths[colorType] {
		if d == depth {
			return true
		}
	}
	return false
}

func zlibHeaderOK(cmf, flg byte) bool {
	return cmf&0x0f == 8 && cmf>>4 <= 7 && (uint16(cmf)<<8|uint16(flg))%31 == 0
}
