package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/store"
)

// TestHandleInterfacesNoStore 验证缺少 store 时返回 400。
func TestHandleInterfacesNoStore(t *testing.T) {
	s := &Server{
		stores:     map[string]*store.Store{"sflow": {}},
		defaultSrc: "sflow",
	}
	// source=missing 不在 stores 中 → storeFor 报错 → 400
	r := httptest.NewRequest("GET", "/api/v1/interfaces?source=missing", nil)
	w := httptest.NewRecorder()
	s.handleInterfaces(w, r, "admin")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400,得到 %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Error("错误响应里没有 error 字段")
	}
}

// TestHandleIfaceSeriesBadParams 验证参数校验。
func TestHandleIfaceSeriesBadParams(t *testing.T) {
	s := &Server{
		stores:     map[string]*store.Store{"sflow": {}},
		defaultSrc: "sflow",
	}

	cases := []struct {
		name string
		url  string
	}{
		// 缺 device_id 意味着 ParseUint("", 10, 32) 会报错
		{"缺 device_id", "/api/v1/interfaces/series?if_index=1"},
		// 缺 if_index 同理
		{"缺 if_index", "/api/v1/interfaces/series?device_id=1"},
		{"device_id 非整数", "/api/v1/interfaces/series?device_id=abc&if_index=1"},
		{"if_index 非整数", "/api/v1/interfaces/series?device_id=1&if_index=x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", c.url, nil)
			w := httptest.NewRecorder()
			s.handleIfaceSeries(w, r, "admin")
			if w.Code != http.StatusBadRequest {
				t.Fatalf("期望 400,得到 %d (url=%s)", w.Code, c.url)
			}
			if !strings.Contains(w.Body.String(), "error") {
				t.Error("400 响应里没有 error 字段")
			}
		})
	}
}
