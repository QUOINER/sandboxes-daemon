package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
	"unicode/utf8"
)

const policySigningDomain = "rheic-policy-payload\x00v1\x00"

// PolicySigningBytes returns the version-1 canonical bytes signed for a policy
// payload. The encoding is independent of JSON formatting and field order.
func PolicySigningBytes(payload PolicyPayload) ([]byte, error) {
	if err := validateCanonicalPolicy(payload); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	encoded.WriteString(policySigningDomain)
	if payload.SchemaVersion < 0 || payload.SchemaVersion > math.MaxUint32 {
		return nil, errors.New("policy schema version exceeds canonical encoding limit")
	}
	writeUint32(&encoded, uint32(payload.SchemaVersion))
	if err := writeString(&encoded, payload.OrgID); err != nil {
		return nil, err
	}
	writeUint64(&encoded, payload.Revision)
	if err := writeInstant(&encoded, payload.IssuedAt); err != nil {
		return nil, err
	}
	if err := writeInstant(&encoded, payload.ExpiresAt); err != nil {
		return nil, err
	}
	if len(payload.Rules) > math.MaxUint32 {
		return nil, errors.New("policy rule count exceeds canonical encoding limit")
	}
	//nolint:gosec // validateCanonicalPolicy caps rule count at 10,000 before this encoding conversion.
	writeUint32(&encoded, uint32(len(payload.Rules)))
	for _, rule := range payload.Rules {
		if err := writeString(&encoded, rule.Resource); err != nil {
			return nil, err
		}
		if err := writeString(&encoded, rule.Action); err != nil {
			return nil, err
		}
		if err := writeString(&encoded, rule.RuleID); err != nil {
			return nil, err
		}
	}
	return encoded.Bytes(), nil
}

// DecodePolicyPayloadJSON decodes a policy while rejecting duplicate JSON
// members, invalid UTF-8 and timestamps with sub-nanosecond precision.
func DecodePolicyPayloadJSON(raw []byte) (PolicyPayload, error) {
	var payload PolicyPayload
	if err := decodeStrictJSON(raw, &payload); err != nil {
		return PolicyPayload{}, err
	}
	if err := validatePolicyTimestampJSON(raw, false); err != nil {
		return PolicyPayload{}, err
	}
	return payload, nil
}

// DecodeSignedPolicyBundleJSON applies the strict JSON rules used for signed
// bundles before decoding their typed representation.
func DecodeSignedPolicyBundleJSON(raw []byte) (SignedPolicyBundle, error) {
	var bundle SignedPolicyBundle
	if err := decodeStrictJSON(raw, &bundle); err != nil {
		return SignedPolicyBundle{}, err
	}
	if err := validatePolicyTimestampJSON(raw, true); err != nil {
		return SignedPolicyBundle{}, err
	}
	return bundle, nil
}

func validateCanonicalPolicy(payload PolicyPayload) error {
	if !validOrgID(payload.OrgID) {
		return errors.New("invalid policy organization ID")
	}
	if err := validatePayloadMetadata(payload, payload.OrgID, payload.IssuedAt); err != nil {
		return err
	}
	return validatePolicyRules(payload.Rules)
}

func writeInstant(buffer *bytes.Buffer, value time.Time) error {
	if err := binary.Write(buffer, binary.BigEndian, value.Unix()); err != nil {
		return err
	}
	nanoseconds := value.Nanosecond()
	if nanoseconds < 0 || nanoseconds > math.MaxUint32 {
		return errors.New("policy timestamp nanoseconds exceed canonical encoding limit")
	}
	writeUint32(buffer, uint32(nanoseconds))
	return nil
}

func writeString(buffer *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("policy string is not valid UTF-8")
	}
	if uint64(len(value)) > math.MaxUint32 {
		return errors.New("policy string exceeds canonical encoding limit")
	}
	//nolint:gosec // The preceding bound check guarantees the byte length fits uint32.
	writeUint32(buffer, uint32(len(value)))
	buffer.WriteString(value)
	return nil
}

func writeUint32(buffer *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	buffer.Write(encoded[:])
}

func decodeStrictJSON(raw []byte, dst any) error {
	if len(raw) > maxBundleBytes {
		return errors.New("JSON document exceeds size limit")
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON document is not valid UTF-8")
	}
	if err := validateJSONUnicodeEscapes(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func validateJSONUnicodeEscapes(raw []byte) error {
	for index := 0; index < len(raw); {
		if raw[index] != '"' {
			index++
			continue
		}
		end, err := scanJSONStringEscapes(raw, index+1)
		if err != nil {
			return err
		}
		index = end + 1
	}
	return nil
}

func scanJSONStringEscapes(raw []byte, index int) (int, error) {
	for index < len(raw) {
		switch raw[index] {
		case '"':
			return index, nil
		case '\\':
			next, err := scanJSONEscape(raw, index)
			if err != nil {
				return 0, err
			}
			index = next
		default:
			index++
		}
	}
	return 0, errors.New("unterminated JSON string")
}

func scanJSONEscape(raw []byte, index int) (int, error) {
	if index+1 >= len(raw) {
		return 0, errors.New("incomplete JSON string escape")
	}
	if raw[index+1] != 'u' {
		return index + 2, nil
	}
	code, ok := readUnicodeEscape(raw[index+2:])
	if !ok {
		return 0, errors.New("invalid JSON Unicode escape")
	}
	if code >= 0xdc00 && code <= 0xdfff {
		return 0, errors.New("unpaired JSON low surrogate")
	}
	if code < 0xd800 || code > 0xdbff {
		return index + 6, nil
	}
	if index+12 > len(raw) || raw[index+6] != '\\' || raw[index+7] != 'u' {
		return 0, errors.New("unpaired JSON high surrogate")
	}
	low, valid := readUnicodeEscape(raw[index+8:])
	if !valid || low < 0xdc00 || low > 0xdfff {
		return 0, errors.New("invalid JSON surrogate pair")
	}
	return index + 12, nil
}

func readUnicodeEscape(raw []byte) (uint16, bool) {
	if len(raw) < 4 {
		return 0, false
	}
	var code uint16
	for _, char := range raw[:4] {
		code <<= 4
		switch {
		case char >= '0' && char <= '9':
			code |= uint16(char - '0')
		case char >= 'a' && char <= 'f':
			code |= uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			code |= uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	return code, true
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return scanJSONObject(decoder)
	case '[':
		return scanJSONArray(decoder)
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func scanJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid JSON object member")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate JSON member %q", key)
		}
		seen[key] = struct{}{}
		if err := scanJSONValue(decoder); err != nil {
			return err
		}
	}
	return consumeJSONDelimiter(decoder, '}')
}

func scanJSONArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := scanJSONValue(decoder); err != nil {
			return err
		}
	}
	return consumeJSONDelimiter(decoder, ']')
}

func consumeJSONDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != want {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}

func validatePolicyTimestampJSON(raw []byte, wrapped bool) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	if wrapped {
		var payloadObject map[string]json.RawMessage
		if err := json.Unmarshal(object["payload"], &payloadObject); err != nil {
			return errors.New("policy payload must be an object")
		}
		object = payloadObject
	}
	for _, name := range []string{"issuedAt", "expiresAt"} {
		value, present := object[name]
		if !present {
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			continue // Typed decoding reports the field type error.
		}
		if !hasNanosecondPrecision(text) {
			return fmt.Errorf("policy timestamp %q exceeds nanosecond precision", name)
		}
	}
	return nil
}

func hasNanosecondPrecision(value string) bool {
	separator := bytes.IndexByte([]byte(value), 'T')
	if separator < 0 {
		return true
	}
	fraction := bytes.IndexByte([]byte(value[separator+1:]), '.')
	if fraction < 0 {
		return true
	}
	start := separator + 1 + fraction + 1
	end := start
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	return end-start <= 9
}

// ValidOrgID reports whether org is a valid organization identifier for policy
// routes and bundles.
func ValidOrgID(org string) bool { return validOrgID(org) }

// VerifyPolicySignature reports whether signature is the canonical Ed25519
// signature over payload using the supplied pinned public key.
func VerifyPolicySignature(payload PolicyPayload, signature string, key ed25519.PublicKey) bool {
	return verifySignature(payload, signature, key)
}
