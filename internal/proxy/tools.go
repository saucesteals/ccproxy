package proxy

import (
	"bytes"
	"strings"
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

func unprefixTools(data []byte) []byte {
	s := string(data)
	for name := range fingerprintedTools {
		s = strings.ReplaceAll(s, toolPrefix+name, name)
	}
	return []byte(s)
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

// toolStripper buffers an SSE stream and strips tool prefixes on complete
// events (delimited by \n\n) to avoid corruption at chunk boundaries.
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
	return unprefixTools(complete)
}

func (ts *toolStripper) Flush() []byte {
	if len(ts.buf) == 0 {
		return nil
	}
	out := unprefixTools(ts.buf)
	ts.buf = nil
	return out
}
