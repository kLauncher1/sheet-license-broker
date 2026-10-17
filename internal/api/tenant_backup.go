package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/backup"
	"github.com/kLauncher1/sheet-license-broker/internal/tenant"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id != "" {
			t, found := s.proxy.GetTenant(id)
			if !found {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
				return
			}
			writeJSON(w, http.StatusOK, t)
			return
		}
		list, _ := s.proxy.ListTenants(r.Context())
		writeJSON(w, http.StatusOK, list)
	case http.MethodPost:
		s.handleRegisterTenant(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRegisterTenant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req tenant.Tenant
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}
	created, err := s.proxy.RegisterTenant(r.Context(), &req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SecretKey string `json:"secret_key"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	encrypted, snapshot, err := s.proxy.ExportBackup(r.Context(), []byte(req.SecretKey))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	res := map[string]interface{}{"status": "success", "checksum": snapshot.Checksum, "timestamp": snapshot.Timestamp.Format(time.RFC3339)}
	if len(encrypted) > 0 {
		res["encrypted_payload"] = hex.EncodeToString(encrypted)
	} else {
		res["snapshot"] = snapshot
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SecretKey        string                 `json:"secret_key"`
		EncryptedPayload string                 `json:"encrypted_payload"`
		Snapshot         *backup.BackupSnapshot `json:"snapshot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	var encBytes []byte
	if req.EncryptedPayload != "" {
		var err error
		if encBytes, err = hex.DecodeString(req.EncryptedPayload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid hex in encrypted_payload"})
			return
		}
	}

	restored, err := s.proxy.RestoreBackup(r.Context(), encBytes, []byte(req.SecretKey), req.Snapshot)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "message": "Backup restored successfully", "checksum": restored.Checksum})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EventType string `json:"event_type"`
		TargetURL string `json:"target_url"`
		Secret    string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TargetURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_url is required"})
		return
	}
	if req.EventType == "" {
		req.EventType = webhook.EventLicenseCreated
	}

	evt := webhook.NewEvent(req.EventType, "test-tenant", map[string]string{"message": "Test webhook delivery probe"})
	if err := s.proxy.Dispatcher().DispatchSync(r.Context(), evt, req.TargetURL, req.Secret); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "delivery_id": evt.ID})
}
