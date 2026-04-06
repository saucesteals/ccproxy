package proxy

import (
	"bytes"
	"strings"

	"github.com/saucesteals/ccproxy/internal/safejson"
)

var fingerprintedTools = map[string]bool{
	"sessions_list":    true,
	"sessions_history": true,
	"sessions_send":    true,
	"sessions_yield":   true,
	"sessions_spawn":   true,
	"session_status":   true,
}

const toolPrefix = "oc_"

var prefixedToolMarker = []byte(toolPrefix)
var dataLinePrefix = []byte("data:")

func prefixTools(obj map[string]any) {
	if tools, ok := obj["tools"].([]any); ok {
		for _, t := range tools {
			prefixToolName(t)
		}
	}
	for _, m := range messagesOf(obj) {
		for _, block := range contentBlocksOf(m) {
			prefixToolName(block)
		}
	}
}

func prefixToolName(v any) {
	b, ok := v.(map[string]any)
	if !ok {
		return
	}
	if name, ok := b["name"].(string); ok && fingerprintedTools[name] {
		b["name"] = toolPrefix + name
	}
}

func unprefixToolName(name string) (string, bool) {
	if !strings.HasPrefix(name, toolPrefix) {
		return name, false
	}
	orig := name[len(toolPrefix):]
	if fingerprintedTools[orig] {
		return orig, true
	}
	return name, false
}

// unprefixResponse handles both SSE and JSON response bodies.
func unprefixResponse(body []byte, contentType string) []byte {
	if strings.Contains(contentType, "text/event-stream") {
		return unprefixSSEEvents(body)
	}
	if !bytes.Contains(body, prefixedToolMarker) {
		return body
	}
	var obj map[string]any
	if err := safejson.Unmarshal(body, &obj); err != nil {
		return body
	}
	if unprefixContentBlocks(obj) {
		if out, err := safejson.Marshal(obj); err == nil {
			return out
		}
	}
	return body
}

func unprefixSSEEvents(data []byte) []byte {
	var result bytes.Buffer
	for len(data) > 0 {
		idx := bytes.Index(data, []byte("\n\n"))
		if idx < 0 {
			result.Write(unprefixSSEEvent(data))
			break
		}
		result.Write(unprefixSSEEvent(data[:idx+2]))
		data = data[idx+2:]
	}
	return result.Bytes()
}

func unprefixSSEEvent(event []byte) []byte {
	if !bytes.Contains(event, prefixedToolMarker) {
		return event
	}

	dataStart, dataEnd := findDataLine(event)
	if dataStart < 0 {
		return event
	}

	data := bytes.TrimSpace(event[dataStart:dataEnd])
	if len(data) == 0 || data[0] != '{' {
		return event
	}

	var obj map[string]any
	if err := safejson.Unmarshal(data, &obj); err != nil {
		return event
	}

	// In streaming, tool names only appear in content_block_start events.
	if obj["type"] != "content_block_start" {
		return event
	}
	cb, ok := obj["content_block"].(map[string]any)
	if !ok {
		return event
	}
	if bType, _ := cb["type"].(string); bType != "tool_use" {
		return event
	}
	name, _ := cb["name"].(string)
	stripped, changed := unprefixToolName(name)
	if !changed {
		return event
	}
	cb["name"] = stripped

	newData, err := safejson.Marshal(obj)
	if err != nil {
		return event
	}

	var buf bytes.Buffer
	buf.Grow(len(event))
	buf.Write(event[:dataStart])
	buf.Write(newData)
	buf.Write(event[dataEnd:])
	return buf.Bytes()
}

// findDataLine returns the value start and line end offsets for the first
// line-anchored "data:" in event. Returns (-1, -1) if not found.
func findDataLine(event []byte) (int, int) {
	offset := 0
	for offset < len(event) {
		nl := bytes.IndexByte(event[offset:], '\n')
		lineEnd := offset + nl
		if nl < 0 {
			lineEnd = len(event)
		}

		if bytes.HasPrefix(event[offset:lineEnd], dataLinePrefix) {
			valStart := offset + len(dataLinePrefix)
			if valStart < len(event) && event[valStart] == ' ' {
				valStart++
			}
			return valStart, lineEnd
		}

		if nl < 0 {
			break
		}
		offset = lineEnd + 1
	}
	return -1, -1
}

func unprefixContentBlocks(msg map[string]any) bool {
	blocks, ok := msg["content"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, block := range blocks {
		b, ok := block.(map[string]any)
		if !ok {
			continue
		}
		if bType, _ := b["type"].(string); bType != "tool_use" {
			continue
		}
		name, _ := b["name"].(string)
		if stripped, ok := unprefixToolName(name); ok {
			b["name"] = stripped
			changed = true
		}
	}
	return changed
}

func messagesOf(obj map[string]any) []any {
	msgs, _ := obj["messages"].([]any)
	return msgs
}

func contentBlocksOf(msg any) []any {
	m, ok := msg.(map[string]any)
	if !ok {
		return nil
	}
	blocks, _ := m["content"].([]any)
	return blocks
}

// toolStripper buffers an SSE stream, emitting complete events (\n\n delimited)
// with tool name prefixes stripped from tool_use blocks.
type toolStripper struct {
	buf []byte
}

func newToolStripper() *toolStripper { return &toolStripper{} }

func (ts *toolStripper) Write(chunk []byte) []byte {
	ts.buf = append(ts.buf, chunk...)

	idx := bytes.LastIndex(ts.buf, []byte("\n\n"))
	if idx < 0 {
		return nil
	}
	idx += 2

	complete := ts.buf[:idx]
	ts.buf = append([]byte(nil), ts.buf[idx:]...)
	return unprefixSSEEvents(complete)
}

func (ts *toolStripper) Flush() []byte {
	if len(ts.buf) == 0 {
		return nil
	}
	out := unprefixSSEEvents(ts.buf)
	ts.buf = nil
	return out
}
