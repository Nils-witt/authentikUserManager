package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"authentikManager/internal/auth"
)

// requireRecentAuth restricts h to operators who authenticated at authentik
// within the last reauthMaxAge. Critical changes, such as adding CAs or deleting users, use it, so
// that an unattended or stolen session cannot make them. Other operators get
// 403 with reauthenticate set: the UI then signs them in again
// (/auth/login?reauth=1) and they repeat the change.
func (s *Server) requireRecentAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFromContext(r.Context())
		recent := s.reauthMaxAge <= 0 || !u.AuthTime.IsZero() && time.Since(u.AuthTime) <= s.reauthMaxAge
		if recent {
			h(w, r)
			return
		}
		safePath := strings.ReplaceAll(r.URL.Path, "\n", "")
		safePath = strings.ReplaceAll(safePath, "\r", "")
		s.logger.InfoContext(r.Context(), "re-authentication required",
			slog.String("username", u.Username),
			slog.String("path", safePath),
		)
		writeJSON(w, http.StatusForbidden, errorBody{Error: "Confirm this change by signing in again.", Reauthenticate: true})
	}
}
