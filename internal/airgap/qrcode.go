package airgap

import (
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"strings"
)

// RFC 9285 Base45 charset (45 characters)
const base45Charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

var base45Lookup = func() [256]int {
	var lookup [256]int
	for i := range lookup {
		lookup[i] = -1
	}
	for i, ch := range base45Charset {
		lookup[ch] = i
	}
	return lookup
}()

// Base45Encode encodes binary data into RFC 9285 Base45 format.
func Base45Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var sb strings.Builder
	// Reserve rough capacity
	sb.Grow((len(data)*3 + 1) / 2)

	i := 0
	for ; i+1 < len(data); i += 2 {
		n := (uint32(data[i]) << 8) | uint32(data[i+1])
		c := n % 45
		n /= 45
		d := n % 45
		e := n / 45
		sb.WriteByte(base45Charset[c])
		sb.WriteByte(base45Charset[d])
		sb.WriteByte(base45Charset[e])
	}

	// Remaining single byte
	if i < len(data) {
		n := uint32(data[i])
		c := n % 45
		d := n / 45
		sb.WriteByte(base45Charset[c])
		sb.WriteByte(base45Charset[d])
	}

	return sb.String()
}

// Base45Decode decodes an RFC 9285 Base45 encoded string into raw bytes.
func Base45Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}

	rem := len(s) % 3
	if rem == 1 {
		return nil, fmt.Errorf("invalid base45 length: remainder 1 not permitted")
	}

	result := make([]byte, 0, (len(s)/3)*2+rem)
	i := 0
	for ; i+2 < len(s); i += 3 {
		c := base45Lookup[s[i]]
		d := base45Lookup[s[i+1]]
		e := base45Lookup[s[i+2]]

		if c < 0 || d < 0 || e < 0 {
			return nil, fmt.Errorf("invalid character in base45 stream at index %d", i)
		}

		val := uint32(c) + uint32(d)*45 + uint32(e)*45*45
		if val > 65535 {
			return nil, fmt.Errorf("base45 triplet value exceeds 16-bit range (%d)", val)
		}

		result = append(result, byte(val>>8), byte(val&0xFF))
	}

	if i+1 < len(s) {
		c := base45Lookup[s[i]]
		d := base45Lookup[s[i+1]]

		if c < 0 || d < 0 {
			return nil, fmt.Errorf("invalid character in base45 remainder at index %d", i)
		}

		val := uint32(c) + uint32(d)*45
		if val > 255 {
			return nil, fmt.Errorf("base45 pair value exceeds 8-bit range (%d)", val)
		}

		result = append(result, byte(val))
	}

	return result, nil
}

// EncodeQRPayload converts arbitrary payload bytes into an air-gapped QR-transferable text representation.
// Envelope format: AIRGAP:B45:<CRC32_HEX>:<BASE45_STRING>
func EncodeQRPayload(payload []byte) string {
	crc := crc32.ChecksumIEEE(payload)
	crcHex := fmt.Sprintf("%08X", crc)
	b45 := Base45Encode(payload)
	return fmt.Sprintf("AIRGAP:B45:%s:%s", crcHex, b45)
}

// DecodeQRPayload extracts and validates payload bytes from an air-gapped QR string with CRC32 integrity check.
func DecodeQRPayload(qrText string) ([]byte, error) {
	trimmed := strings.TrimSpace(qrText)
	parts := strings.Split(trimmed, ":")
	if len(parts) < 4 || parts[0] != "AIRGAP" || parts[1] != "B45" {
		return nil, ErrInvalidActivationPayload
	}

	expectedCrcHex := parts[2]
	b45Data := strings.Join(parts[3:], ":") // Handle any subsequent colons safely

	decoded, err := Base45Decode(b45Data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidActivationPayload, err)
	}

	// Validate CRC32 checksum
	actualCrc := crc32.ChecksumIEEE(decoded)
	expectedCrcBytes, err := hex.DecodeString(expectedCrcHex)
	if err != nil || len(expectedCrcBytes) != 4 {
		return nil, ErrCorruptedQRPayload
	}

	expectedCrc := (uint32(expectedCrcBytes[0]) << 24) |
		(uint32(expectedCrcBytes[1]) << 16) |
		(uint32(expectedCrcBytes[2]) << 8) |
		uint32(expectedCrcBytes[3])

	if actualCrc != expectedCrc {
		return nil, ErrCorruptedQRPayload
	}

	return decoded, nil
}
