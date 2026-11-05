package oauthsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const maxInterceptedTokenResponse = 64 << 10

// ResponseFields selects the provider's OAuth token response fields. Empty
// fields use the OAuth 2.0 defaults.
type ResponseFields struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    string
	Scope        string
	IDToken      string
}

// Sentinels are stable per sandbox and never grant host-side authority.
type Sentinels struct {
	AccessToken  string
	RefreshToken string
}

// InterceptTokenResponse stores real tokens in the returned host-only Tokens
// value and returns a JSON response with guest sentinels. The input is bounded,
// strict JSON, and must contain exactly one non-empty access token.
func InterceptTokenResponse(body []byte, fields ResponseFields, sentinels Sentinels) ([]byte, Tokens, error) {
	if len(body) == 0 || len(body) > maxInterceptedTokenResponse || sentinels.AccessToken == "" || sentinels.RefreshToken == "" || sentinels.AccessToken == sentinels.RefreshToken {
		return nil, Tokens{}, errors.New("invalid OAuth token response configuration")
	}
	fields = normalizedResponseFields(fields)
	if !validResponseFields(fields) {
		return nil, Tokens{}, errors.New("invalid OAuth response fields")
	}
	response, err := decodeUniqueJSONObject(body)
	if err != nil {
		return nil, Tokens{}, err
	}
	tokens, err := parseHostTokens(response, fields)
	if err != nil {
		return nil, Tokens{}, err
	}
	filtered, err := sanitizeTokenResponse(response, fields, sentinels)
	if err != nil {
		return nil, Tokens{}, err
	}
	return filtered, tokens, nil
}

func parseHostTokens(response map[string]json.RawMessage, fields ResponseFields) (Tokens, error) {
	tokens := Tokens{TokenType: "Bearer"}
	var err error
	if tokens.AccessToken, err = readRequiredString(response, fields.AccessToken); err != nil {
		return Tokens{}, err
	}
	if tokens.RefreshToken, err = readOptionalString(response, fields.RefreshToken); err != nil {
		return Tokens{}, err
	}
	if tokens.IDToken, err = readOptionalString(response, fields.IDToken); err != nil {
		return Tokens{}, err
	}
	if tokens.ExpiresIn, err = readOptionalInt64(response, fields.ExpiresIn); err != nil || tokens.ExpiresIn < 0 {
		return Tokens{}, errors.New("invalid OAuth token expiry")
	}
	tokenType, err := readOptionalString(response, "token_type")
	if err != nil || tokenType != "" && !strings.EqualFold(tokenType, "Bearer") {
		return Tokens{}, errors.New("unsupported OAuth token type")
	}
	scope, err := readOptionalString(response, fields.Scope)
	if err != nil {
		return Tokens{}, err
	}
	tokens.Scopes = strings.Fields(scope)
	return tokens, nil
}

func sanitizeTokenResponse(response map[string]json.RawMessage, fields ResponseFields, sentinels Sentinels) ([]byte, error) {
	access, err := json.Marshal(sentinels.AccessToken)
	if err != nil {
		return nil, errors.New("encode OAuth access sentinel")
	}
	response[fields.AccessToken] = access
	if _, exists := response[fields.RefreshToken]; exists {
		refresh, err := json.Marshal(sentinels.RefreshToken)
		if err != nil {
			return nil, errors.New("encode OAuth refresh sentinel")
		}
		response[fields.RefreshToken] = refresh
	}
	delete(response, fields.IDToken)
	filtered, err := json.Marshal(response)
	if err != nil || len(filtered) > maxInterceptedTokenResponse {
		clear(filtered)
		return nil, errors.New("OAuth token response exceeds limits")
	}
	return filtered, nil
}

func decodeUniqueJSONObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("invalid OAuth token response")
	}
	values := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return nil, errors.New("invalid OAuth token response")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("duplicate OAuth token response field")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errors.New("invalid OAuth token response")
		}
		values[key] = value
	}
	if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
		return nil, errors.New("invalid OAuth token response")
	}
	if trailingErr := decoder.Decode(new(any)); !errors.Is(trailingErr, io.EOF) {
		return nil, errors.New("invalid trailing OAuth token response data")
	}
	return values, nil
}

// RestoreRefreshToken replaces only the configured sentinel in a bounded form
// body for an OAuth refresh grant. It rejects duplicate grant/token fields.
func RestoreRefreshToken(body []byte, sentinel, refreshToken string) ([]byte, bool, error) {
	if len(body) == 0 || len(body) > maxInterceptedTokenResponse || sentinel == "" || refreshToken == "" {
		return nil, false, errors.New("invalid OAuth refresh request")
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, false, errors.New("invalid OAuth refresh form")
	}
	grants := values["grant_type"]
	if len(grants) != 1 {
		return nil, false, errors.New("invalid OAuth grant type field")
	}
	if grants[0] != refreshGrant {
		return append([]byte(nil), body...), false, nil
	}
	refreshValues := values[refreshGrant]
	if len(refreshValues) != 1 {
		return nil, false, errors.New("invalid OAuth refresh token field")
	}
	if refreshValues[0] != sentinel {
		return append([]byte(nil), body...), false, nil
	}
	values.Set(refreshGrant, refreshToken)
	return []byte(values.Encode()), true, nil
}

func normalizedResponseFields(fields ResponseFields) ResponseFields {
	if fields.AccessToken == "" {
		fields.AccessToken = "access_token"
	}
	if fields.RefreshToken == "" {
		fields.RefreshToken = "refresh_token"
	}
	if fields.ExpiresIn == "" {
		fields.ExpiresIn = "expires_in"
	}
	if fields.Scope == "" {
		fields.Scope = "scope"
	}
	if fields.IDToken == "" {
		fields.IDToken = "id_token"
	}
	return fields
}

func validResponseFields(fields ResponseFields) bool {
	seen := make(map[string]struct{}, 5)
	for _, name := range []string{fields.AccessToken, fields.RefreshToken, fields.ExpiresIn, fields.Scope, fields.IDToken, "token_type"} {
		if name == "" || len(name) > 64 || strings.ContainsAny(name, "\x00\r\n") {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func readRequiredString(values map[string]json.RawMessage, key string) (string, error) {
	value, err := readOptionalString(values, key)
	if err != nil || value == "" {
		return "", errors.New("OAuth token response is missing a required token")
	}
	return value, nil
}

func readOptionalString(values map[string]json.RawMessage, key string) (string, error) {
	raw, exists := values[key]
	if !exists {
		return "", nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", errors.New("invalid OAuth token response field")
	}
	return value, nil
}

func readOptionalInt64(values map[string]json.RawMessage, key string) (int64, error) {
	raw, exists := values[key]
	if !exists {
		return 0, nil
	}
	var number json.Number
	if json.Unmarshal(raw, &number) != nil {
		return 0, errors.New("invalid OAuth token expiry")
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return 0, errors.New("invalid OAuth token expiry")
	}
	return value, nil
}
