package api

import (
	"net/http"

	"github.com/xeron-be/xeron-mx/internal/dmarc"
)

func (s *Server) handleGetDMARC(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}

	arcEnabled := false
	if k, err := s.db.DKIMKeyFor(r.Context(), d.ID); err == nil && k != nil && k.Enabled {
		arcEnabled = true
	}

	check, _ := dmarc.CheckDNS(r.Context(), d.Name)

	s.ok(w, http.StatusOK, map[string]any{
		"domain": d.Name,
		"record": map[string]string{
			"type":  "TXT",
			"name":  dmarc.RecordName(d.Name),
			"value": dmarc.DefaultValue(d.Name, "quarantine"),
			"note":  "DMARC policy record for domain email authentication and anti-spoofing.",
		},
		"dns":         check,
		"arc_enabled": arcEnabled,
	})
}

func (s *Server) handleCheckDMARC(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	check, err := dmarc.CheckDNS(r.Context(), d.Name)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMReadFailed)
		return
	}
	s.ok(w, http.StatusOK, check)
}
