// Package reqlog ties log records to the HTTP request they were written for,
// by a request ID carried in the context.
package reqlog

import (
	"context"
	"log/slog"
)

type requestIDKey struct{}

// WithRequestID returns a copy of ctx carrying the request ID id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request ID of ctx, or "" when it has none.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// Handler adds the request ID of the context, if any, to every record as
// "request_id", so all records written for one request can be found.
type Handler struct {
	slog.Handler
}

// NewHandler wraps h.
func NewHandler(h slog.Handler) *Handler {
	return &Handler{Handler: h}
}

// Handle adds the request ID and passes the record on.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r = r.Clone()
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs returns a Handler whose records also carry attrs.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup returns a Handler that nests later attributes in the group name.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{Handler: h.Handler.WithGroup(name)}
}
