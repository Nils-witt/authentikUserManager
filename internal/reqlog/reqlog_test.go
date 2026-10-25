package reqlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"authentikManager/internal/reqlog"
)

func TestHandler(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(reqlog.NewHandler(slog.NewJSONHandler(&buf, nil))).With(slog.String("app", "am"))

	logger.InfoContext(reqlog.WithRequestID(context.Background(), "r1"), "with id")
	logger.InfoContext(context.Background(), "without id")

	dec := json.NewDecoder(&buf)
	for _, want := range []string{"r1", ""} {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		got, _ := rec["request_id"].(string)
		if got != want || rec["app"] != "am" {
			t.Errorf("record %v: request_id = %q, want %q, with app attribute", rec, got, want)
		}
	}
}
