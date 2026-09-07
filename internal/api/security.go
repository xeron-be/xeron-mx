package api

import (
	"context"
	"net/http"
	"time"
)

type securityStatusResponse struct {
	DNSBL  dnsblStatus  `json:"dnsbl"`
	ClamAV clamavStatus `json:"clamav"`
	Rspamd rspamdStatus `json:"rspamd"`
}

type dnsblStatus struct {
	Enabled bool     `json:"enabled"`
	Zones   []string `json:"zones"`
}

type clamavStatus struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
	Status  string `json:"status"`
	Action  string `json:"action"`
}

type rspamdStatus struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	resp := securityStatusResponse{
		DNSBL: dnsblStatus{
			Enabled: false,
			Zones:   []string{},
		},
		ClamAV: clamavStatus{
			Enabled: false,
			Status:  "disabled",
		},
		Rspamd: rspamdStatus{
			Enabled: false,
		},
	}

	if s.dnsbl != nil {
		resp.DNSBL.Enabled = s.dnsbl.Enabled()
		resp.DNSBL.Zones = s.dnsbl.Zones()
	}

	if s.clamav != nil {
		resp.ClamAV.Enabled = s.clamav.Enabled()
		resp.ClamAV.Addr = s.clamav.Addr()
		resp.ClamAV.Action = s.clamav.Action()
		if s.clamav.Enabled() {
			ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
			defer cancel()
			if err := s.clamav.Ping(ctx); err == nil {
				resp.ClamAV.Status = "online"
			} else {
				resp.ClamAV.Status = "offline"
			}
		} else {
			resp.ClamAV.Status = "disabled"
		}
	}

	if s.spam != nil && s.spam.Enabled() {
		resp.Rspamd.Enabled = true
	}

	s.ok(w, http.StatusOK, resp)
}

type dnsblTestRequest struct {
	IP string `json:"ip"`
}

func (s *Server) handleTestDNSBL(w http.ResponseWriter, r *http.Request) {
	var req dnsblTestRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if req.IP == "" {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidIP)
		return
	}

	if s.dnsbl == nil {
		s.fail(w, r, http.StatusServiceUnavailable, ErrDNSBLNotConfigured)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	res, err := s.dnsbl.CheckDetailed(ctx, req.IP)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidIP)
		return
	}

	s.ok(w, http.StatusOK, res)
}
