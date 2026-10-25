package server

import (
	"log/slog"
	"net/http"
	"time"

	"authentikManager/internal/auth"
)

// requireRecentAuth restricts h to operators who authenticated at authentik
// within the last reauthMaxAge and, with requireMFA, with more than one
// factor. Critical changes, such as adding CAs or deleting users, use it, so
// that an unattended or stolen session cannot make them. Other operators get
// 403 with reauthenticate set: the UI then signs them in again
// (/auth/login?reauth=1) and they repeat the change.
func (s *Server) requireRecentAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFromContext(r.Context())
		recent := s.reauthMaxAge <= 0 || !u.AuthTime.IsZero() && time.Since(u.AuthTime) <= s.reauthMaxAge
		mfa := !s.requireMFA || u.MFA()
		if recent && mfa {
			h(w, r)
			return
		}
		s.logger.InfoContext(r.Context(), "re-authentication required",
			slog.String("username", u.Username),
			slog.String("path", r.URL.Path),
			slog.Bool("recent", recent),
			slog.Bool("mfa", mfa),
		)
		msg := "Confirm this change by signing in again."
		if !mfa {
			msg = "This change requires signing in with multi-factor authentication."
		}
		writeJSON(w, http.StatusForbidden, errorBody{Error: msg, Reauthenticate: true})
	}
}
