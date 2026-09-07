package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/xeron-be/xeron-mx/internal/dkim"
	"github.com/xeron-be/xeron-mx/internal/smtpclient"
	"github.com/xeron-be/xeron-mx/internal/store"
)

type dkimRequest struct {
	Selector  string `json:"selector"`
	Algorithm string `json:"algorithm"`
	Enabled   *bool  `json:"enabled"`
	Force     bool   `json:"force"`
}

func (s *Server) dkimJSON(d *store.Domain, k *store.DKIMKey) map[string]any {
	return map[string]any{
		"domain":     d.Name,
		"selector":   k.Selector,
		"algorithm":  k.Algorithm,
		"enabled":    k.Enabled,
		"created_at": k.CreatedAt,
		"record": map[string]string{
			"type":  "TXT",
			"name":  dkim.RecordName(k.Selector, d.Name),
			"value": dkim.RecordValue(k.Algorithm, k.PublicKey),
			"note": "Publish this before enabling the key, or mail signed with it fails " +
				"verification and looks worse than unsigned mail would.",
		},
	}
}

func (s *Server) handleGetDKIM(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	k, err := s.db.DKIMKeyFor(r.Context(), d.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.ok(w, http.StatusOK, map[string]any{"domain": d.Name, "configured": false})
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMReadFailed)
		return
	}
	out := s.dkimJSON(d, k)
	out["configured"] = true
	s.ok(w, http.StatusOK, out)
}

func (s *Server) handleCreateDKIM(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}

	var req dkimRequest
	if err := decode(w, r, &req); err != nil && err.Error() != "EOF" {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if req.Algorithm != "" && !store.ValidDKIMAlgorithm(req.Algorithm) {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidAlgorithm)
		return
	}

	key, err := dkim.Generate(req.Selector, req.Algorithm)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidAlgorithm)
		return
	}
	sealed, err := s.blobs.Seal(key.PrivatePEM)
	if err != nil {
		s.log.Error("could not seal the dkim key", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMSealFailed)
		return
	}

	stored := &store.DKIMKey{
		DomainID: d.ID, Selector: key.Selector, Algorithm: key.Algorithm,
		PrivateKey: sealed, PublicKey: key.PublicB64, Enabled: false,
	}
	if err := s.db.SaveDKIMKey(r.Context(), stored); err != nil {
		s.log.Error("could not save the dkim key", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMSaveFailed)
		return
	}

	admin := userFrom(r)
	s.log.Info("dkim key generated", "domain", d.Name, "selector", key.Selector, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "dkim_key_created", DomainID: &d.ID, UserID: &admin.ID,
		Data: map[string]any{"domain": d.Name, "selector": key.Selector,
			"algorithm": key.Algorithm},
	})

	out := s.dkimJSON(d, stored)
	out["configured"] = true
	s.ok(w, http.StatusCreated, out)
}

func (s *Server) handleCheckDKIM(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	k, err := s.db.DKIMKeyFor(r.Context(), d.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrDKIMNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMReadFailed)
		return
	}
	check, err := dkim.CheckDNS(r.Context(), d.Name, k.Selector, k.PublicKey)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMReadFailed)
		return
	}
	s.ok(w, http.StatusOK, check)
}

func (s *Server) handleUpdateDKIM(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	var req dkimRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	if req.Enabled == nil {
		s.fail(w, r, http.StatusBadRequest, ErrDKIMUpdateFailed)
		return
	}
	if *req.Enabled && !req.Force {
		k, err := s.db.DKIMKeyFor(r.Context(), d.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.fail(w, r, http.StatusNotFound, ErrDKIMNotFound)
				return
			}
			s.fail(w, r, http.StatusInternalServerError, ErrDKIMReadFailed)
			return
		}
		check, checkErr := dkim.CheckDNS(r.Context(), d.Name, k.Selector, k.PublicKey)
		if checkErr != nil || (check != nil && !check.Valid) {
			s.fail(w, r, http.StatusUnprocessableEntity, ErrDKIMDNSMissing)
			return
		}
	}
	if err := s.db.SetDKIMEnabled(r.Context(), d.ID, *req.Enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrDKIMNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMUpdateFailed)
		return
	}
	s.log.Info("dkim signing toggled", "domain", d.Name, "enabled", *req.Enabled)
	k, err := s.db.DKIMKeyFor(r.Context(), d.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMReadFailed)
		return
	}
	out := s.dkimJSON(d, k)
	out["configured"] = true
	s.ok(w, http.StatusOK, out)
}

func (s *Server) handleDeleteDKIM(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDomain(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteDKIMKey(r.Context(), d.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrDKIMNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrDKIMDeleteFailed)
		return
	}
	admin := userFrom(r)
	s.log.Warn("dkim key deleted", "domain", d.Name, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "dkim_key_deleted", DomainID: &d.ID, UserID: &admin.ID,
		Data: map[string]any{"domain": d.Name},
	})
	s.ok(w, http.StatusOK, map[string]any{"deleted": d.Name})
}

type routeRequest struct {
	Destination   string `json:"destination"`
	Mode          string `json:"mode"`
	RelayHost     string `json:"relay_host"`
	RelayPort     int    `json:"relay_port"`
	RelayTLS      string `json:"relay_tls"`
	RelayUsername string `json:"relay_username"`
	RelayPassword string `json:"relay_password"`
	Enabled       *bool  `json:"enabled"`
}

func routeJSON(r *store.Route) map[string]any {
	return map[string]any{
		"id": r.ID, "destination": r.Destination, "mode": r.Mode,
		"relay_host": r.RelayHost, "relay_port": r.RelayPort,
		"relay_tls": r.RelayTLS, "relay_username": r.RelayUsername,
		"has_password": len(r.RelayPassword) > 0,
		"enabled":      r.Enabled, "created_at": r.CreatedAt,
	}
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := s.db.ListRoutes(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrRouteListFailed)
		return
	}
	out := make([]map[string]any, 0, len(routes))
	for _, rt := range routes {
		out = append(out, routeJSON(rt))
	}
	s.ok(w, http.StatusOK, map[string]any{"routes": out})
}

func (s *Server) routeFromRequest(req *routeRequest, existing *store.Route) (*store.Route, string) {
	rt := &store.Route{Mode: "relay", RelayPort: 587, RelayTLS: smtpclient.TLSRequired, Enabled: true}
	if existing != nil {
		rt = &store.Route{
			ID: existing.ID, Destination: existing.Destination, Mode: existing.Mode,
			RelayHost: existing.RelayHost, RelayPort: existing.RelayPort,
			RelayTLS: existing.RelayTLS, RelayUsername: existing.RelayUsername,
			RelayPassword: existing.RelayPassword, Enabled: existing.Enabled,
		}
	}

	if req.Destination != "" {
		rt.Destination = strings.ToLower(strings.TrimSpace(req.Destination))
	}
	if rt.Destination == "" {
		return nil, ErrInvalidRoute
	}
	bare := strings.TrimPrefix(rt.Destination, ".")
	if !strings.Contains(bare, ".") || strings.ContainsAny(rt.Destination, " @/\\") {
		return nil, ErrInvalidRoute
	}

	if req.Mode != "" {
		rt.Mode = req.Mode
	}
	if rt.Mode != "relay" && rt.Mode != "direct" {
		return nil, ErrInvalidRoute
	}

	if req.RelayHost != "" {
		rt.RelayHost = strings.TrimSpace(req.RelayHost)
	}
	if rt.Mode == "relay" && rt.RelayHost == "" {
		return nil, ErrInvalidRoute
	}
	if req.RelayPort != 0 {
		rt.RelayPort = req.RelayPort
	}
	if rt.RelayPort < 1 || rt.RelayPort > 65535 {
		return nil, ErrInvalidRoute
	}
	if req.RelayTLS != "" {
		rt.RelayTLS = req.RelayTLS
	}
	if !smtpclient.ValidTLSMode(rt.RelayTLS) {
		return nil, ErrInvalidRoute
	}
	if req.RelayUsername != "" {
		rt.RelayUsername = strings.TrimSpace(req.RelayUsername)
	}
	if req.Enabled != nil {
		rt.Enabled = *req.Enabled
	}
	return rt, ""
}

func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	var req routeRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	rt, errMsg := s.routeFromRequest(&req, nil)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}
	if req.RelayPassword != "" {
		sealed, err := s.blobs.Seal([]byte(req.RelayPassword))
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, ErrRouteCreateFailed)
			return
		}
		rt.RelayPassword = sealed
	}

	id, err := s.db.CreateRoute(r.Context(), rt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			s.fail(w, r, http.StatusConflict, ErrRouteExists)
			return
		}
		s.log.Error("create route failed", "error", err)
		s.fail(w, r, http.StatusInternalServerError, ErrRouteCreateFailed)
		return
	}
	rt.ID = id
	if stored, err := s.db.RouteByID(r.Context(), id); err == nil {
		rt = stored
	}

	admin := userFrom(r)
	s.log.Info("outbound route added", "destination", rt.Destination, "mode", rt.Mode, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "route_created", UserID: &admin.ID,
		Data: map[string]any{"destination": rt.Destination, "mode": rt.Mode},
	})
	s.ok(w, http.StatusCreated, routeJSON(rt))
}

func (s *Server) handleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidRouteID)
		return
	}
	existing, err := s.db.RouteByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, ErrRouteNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrRouteListFailed)
		return
	}

	var req routeRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidBody)
		return
	}
	rt, errMsg := s.routeFromRequest(&req, existing)
	if errMsg != "" {
		s.fail(w, r, http.StatusBadRequest, errMsg)
		return
	}
	if req.RelayPassword != "" {
		sealed, err := s.blobs.Seal([]byte(req.RelayPassword))
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, ErrRouteUpdateFailed)
			return
		}
		rt.RelayPassword = sealed
	}
	if err := s.db.UpdateRoute(r.Context(), rt); err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrRouteUpdateFailed)
		return
	}
	s.ok(w, http.StatusOK, routeJSON(rt))
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, ErrInvalidRouteID)
		return
	}
	if err := s.db.DeleteRoute(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, ErrRouteNotFound)
			return
		}
		s.fail(w, r, http.StatusInternalServerError, ErrRouteDeleteFailed)
		return
	}
	admin := userFrom(r)
	s.log.Warn("outbound route deleted", "id", id, "by", admin.Email)
	s.db.RecordEvent(r.Context(), &store.Event{
		Type: "route_deleted", UserID: &admin.ID, Data: map[string]any{"id": id},
	})
	s.ok(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleTestRoute(w http.ResponseWriter, r *http.Request) {
	dest := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("destination")))
	if dest == "" {
		s.fail(w, r, http.StatusBadRequest, ErrMissingDestination)
		return
	}

	rt, err := s.db.RouteFor(r.Context(), dest)
	if errors.Is(err, store.ErrNotFound) {
		s.ok(w, http.StatusOK, map[string]any{
			"destination": dest,
			"matched":     false,
			"mode":        s.outbound.Mode,
			"relay_host":  s.outbound.RelayHost,
			"source":      "the global outbound settings",
		})
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, ErrRouteListFailed)
		return
	}
	s.ok(w, http.StatusOK, map[string]any{
		"destination": dest,
		"matched":     true,
		"route":       rt.Destination,
		"mode":        rt.Mode,
		"relay_host":  rt.RelayHost,
		"source":      "a configured route",
	})
}
