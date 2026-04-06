// Package safejson wraps encoding/json with HTML escaping disabled.
package safejson

import (
	"bytes"
	"encoding/json"
	"io"
)

type (
	RawMessage            = json.RawMessage
	Number                = json.Number
	Token                 = json.Token
	Delim                 = json.Delim
	Decoder               = json.Decoder
	Marshaler             = json.Marshaler
	Unmarshaler           = json.Unmarshaler
	InvalidUnmarshalError = json.InvalidUnmarshalError
	MarshalerError        = json.MarshalerError
	SyntaxError           = json.SyntaxError
	UnmarshalTypeError    = json.UnmarshalTypeError
)

func Unmarshal(data []byte, v any) error          { return json.Unmarshal(data, v) }
func Valid(data []byte) bool                      { return json.Valid(data) }
func Compact(dst *bytes.Buffer, src []byte) error { return json.Compact(dst, src) }
func NewDecoder(r io.Reader) *json.Decoder        { return json.NewDecoder(r) }
