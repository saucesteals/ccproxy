package proxy

import (
	"fmt"
	"strings"

	"github.com/saucesteals/ccproxy/internal/cch"
	"github.com/saucesteals/ccproxy/internal/safejson"
)

var blockedStrings = [][2]string{
	{"You are a personal assistant running inside OpenClaw.", "You are a helpful AI assistant."},
	{"as a heartbeat ack (and may discard it)", "treated as a no-op acknowledgment"},
	{"openclaw.inbound_meta.v1", "msg.meta.v1"},
}

func (h *Handler) rewriteMessages(body []byte) ([]byte, string, error) {
	var obj map[string]any
	if err := safejson.Unmarshal(body, &obj); err != nil {
		return nil, "", fmt.Errorf("unmarshal: %w", err)
	}

	if err := h.stampMetadata(obj); err != nil {
		return nil, "", fmt.Errorf("stamp metadata: %w", err)
	}
	prefixTools(obj)
	hash := cch.Fingerprint(firstUserMessage(obj), h.version)
	h.rewriteSystem(obj, hash)

	out, err := safejson.Marshal(obj)
	if err != nil {
		return nil, "", fmt.Errorf("marshal: %w", err)
	}
	return finalizeCCH(out), hash, nil
}

func (h *Handler) stampMetadata(obj map[string]any) error {
	id := h.auth.Identity()
	uid, err := safejson.Marshal(map[string]string{
		"device_id":    id.DeviceID,
		"account_uuid": id.AccountUUID,
		"session_id":   h.auth.SessionID(),
	})
	if err != nil {
		return fmt.Errorf("marshal user_id: %w", err)
	}
	obj["metadata"] = map[string]any{
		"user_id": string(uid),
	}
	return nil
}

func (h *Handler) rewriteSystem(obj map[string]any, hash string) {
	billing := fmt.Sprintf(
		"x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; %s;",
		h.version, hash, cch.Placeholder,
	)
	billingBlock := map[string]any{"type": "text", "text": billing}

	sys, _ := obj["system"].([]any)
	if len(sys) == 0 {
		obj["system"] = []any{billingBlock}
		return
	}

	replaced := false
	for _, item := range sys {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		text, ok := block["text"].(string)
		if !ok {
			continue
		}

		if strings.Contains(text, "x-anthropic-billing-header") {
			block["text"] = billing
			replaced = true
		} else {
			block["text"] = replaceBlockedStrings(text)
		}
	}

	if !replaced {
		obj["system"] = append([]any{billingBlock}, sys...)
	}
}

func firstUserMessage(obj map[string]any) string {
	msgs, _ := obj["messages"].([]any)
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok || msg["role"] != "user" {
			continue
		}
		switch c := msg["content"].(type) {
		case string:
			return c
		case []any:
			for _, block := range c {
				b, ok := block.(map[string]any)
				if ok && b["type"] == "text" {
					if text, ok := b["text"].(string); ok {
						return text
					}
				}
			}
		}
		break
	}
	return ""
}

func replaceBlockedStrings(text string) string {
	for _, pair := range blockedStrings {
		text = strings.ReplaceAll(text, pair[0], pair[1])
	}
	return text
}

func finalizeCCH(body []byte) []byte {
	s := string(body)
	if !strings.Contains(s, cch.Placeholder) {
		return body
	}
	return []byte(strings.Replace(s, cch.Placeholder, "cch="+cch.Attestation(body), 1))
}
