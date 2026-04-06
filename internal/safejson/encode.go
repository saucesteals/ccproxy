package safejson

import (
	"bytes"
	"encoding/json"
	"io"
)

// encodeInto marshals v into buf, stripping the trailing '\n' from Encode.
func encodeInto(buf *bytes.Buffer, enc *json.Encoder, v any) error {
	if err := enc.Encode(v); err != nil {
		return err
	}
	buf.Truncate(buf.Len() - 1)
	return nil
}

func safeEncoder(buf *bytes.Buffer) *json.Encoder {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	return enc
}

// Marshal returns the JSON encoding of v without HTML escaping.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeInto(&buf, safeEncoder(&buf), v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalIndent is like Marshal but applies indentation.
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := safeEncoder(&buf)
	enc.SetIndent(prefix, indent)
	if err := encodeInto(&buf, enc, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Encoder writes JSON to a stream without HTML escaping or trailing newlines.
type Encoder struct {
	buf bytes.Buffer
	enc *json.Encoder
	w   io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	e := &Encoder{w: w}
	e.enc = safeEncoder(&e.buf)
	return e
}

func (e *Encoder) SetIndent(prefix, indent string) {
	e.enc.SetIndent(prefix, indent)
}

func (e *Encoder) Encode(v any) error {
	e.buf.Reset()
	if err := encodeInto(&e.buf, e.enc, v); err != nil {
		return err
	}
	_, err := e.w.Write(e.buf.Bytes())
	return err
}
