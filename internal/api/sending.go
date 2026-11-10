package api

import (
	"context"
	"net/http"
	"time"

	"github.com/xeron-be/xeron-mx/internal/ses"
	"github.com/xeron-be/xeron-mx/internal/store"
)

func protectionJSON(m *ses.Monitor) map[string]any {
	p := m.Protection()
	return map[string]any{
		"window_hours":           int(p.Window / time.Hour),
		"warn_bounce_percent":    p.WarnBouncePercent,
		"warn_min_bounces":       p.WarnMinBounces,
		"suspend_bounce_percent": p.SuspendBouncePercent,
		"suspend_min_bounces":    p.SuspendMinBounces,
		"warn_complaints":        p.WarnComplaints,
		"suspend_complaints":     p.SuspendComplaints,
	}
}

// sendingLevel is the one-word state the domain list shows.
func (s *Server) sendingLevel(ctx context.Context, d *store.Domain) string {
	if s.sending != nil {
		w, st, err := s.sending.Window(ctx, d)
		if err != nil {
			return ses.LevelOK
		}
		if st.Suspended() {
			return ses.LevelSuspended
		}
		level, _ := ses.Assess(s.sending.Protection(), w)
		if level == ses.LevelSuspended {
			// Reached, but the monitor has not acted on it yet: it will on
			// the next event. Say what is true now.
			return ses.LevelWarning
		}
		return level
	}
	st, err := s.db.SendingStateFor(ctx, d.ID)
	if err == nil && st.Suspended() {
		return ses.LevelSuspended
	}
	return ses.LevelOK
}

func (s *Server) handleGetSending(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	out, err := s.sendingJSON(r.Context(), d)
	if err != nil {
		s.log.Error("read sending state failed", "domain", d.Name, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrSendingReadFailed)
		return
	}
	s.ok(w, http.StatusOK, out)
}

func (s *Server) sendingJSON(ctx context.Context, d *store.Domain) (map[string]any, error) {
	st, err := s.db.SendingStateFor(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"domain":           d.Name,
		"monitored":        s.sending != nil,
		"suspended":        st.Suspended(),
		"suspended_at":     st.SuspendedAt,
		"suspended_reason": st.SuspendedReason,
		"suspended_by":     st.SuspendedBy,
		"level":            s.sendingLevel(ctx, d),
	}
	if s.sending == nil {
		return out, nil
	}
	win, _, err := s.sending.Window(ctx, d)
	if err != nil {
		return nil, err
	}
	feedback, err := s.db.RecentFeedback(ctx, d.ID, 50)
	if err != nil {
		return nil, err
	}
	list := make([]map[string]any, 0, len(feedback))
	for _, f := range feedback {
		list = append(list, map[string]any{
			"kind": f.Kind, "sender": f.Sender, "recipient": f.Recipient,
			"detail": f.Detail, "occurred_at": f.OccurredAt,
		})
	}
	out["since"] = win.Since
	out["sent"] = win.Sent
	out["bounces"] = win.Bounces
	out["complaints"] = win.Complaints
	out["bounce_percent"] = ses.BouncePercent(win)
	out["limits"] = protectionJSON(s.sending)
	out["feedback"] = list
	return out, nil
}

func (s *Server) handleSuspendSending(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	changed, err := ses.SuspendDomain(ctx, s.db, d, userFrom(r).Email, time.Now())
	if err != nil {
		s.log.Error("suspend sending failed", "domain", d.Name, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrSendingUpdateFailed)
		return
	}
	if !changed {
		s.fail(w, r, http.StatusConflict, ErrSendingAlreadySuspended)
		return
	}
	id := d.ID
	s.log.Warn("sending suspended by hand", "domain", d.Name)
	s.audit(ctx, r, &store.Event{
		Type: store.EventSendingSuspended, DomainID: &id,
		Data: map[string]any{"domain": d.Name, "reason": ses.ReasonManual},
	})
	s.writeSending(w, r, d)
}

func (s *Server) handleResumeSending(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	changed, err := s.db.ResumeSending(ctx, d.ID, time.Now())
	if err != nil {
		s.log.Error("resume sending failed", "domain", d.Name, "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrSendingUpdateFailed)
		return
	}
	if !changed {
		s.fail(w, r, http.StatusConflict, ErrSendingNotSuspended)
		return
	}
	id := d.ID
	s.log.Info("sending resumed", "domain", d.Name)
	s.audit(ctx, r, &store.Event{
		Type: store.EventSendingResumed, DomainID: &id,
		Data: map[string]any{"domain": d.Name},
	})
	s.writeSending(w, r, d)
}

func (s *Server) writeSending(w http.ResponseWriter, r *http.Request, d *store.Domain) {
	out, err := s.sendingJSON(r.Context(), d)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrSendingReadFailed)
		return
	}
	s.ok(w, http.StatusOK, out)
}
