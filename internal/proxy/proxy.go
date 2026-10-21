package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anomaly"
	"github.com/kLauncher1/sheet-license-broker/internal/attestation"
	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/auth"
	"github.com/kLauncher1/sheet-license-broker/internal/consensus"
	"github.com/kLauncher1/sheet-license-broker/internal/db"
	"github.com/kLauncher1/sheet-license-broker/internal/enclave"
	"github.com/kLauncher1/sheet-license-broker/internal/feature"
	"github.com/kLauncher1/sheet-license-broker/internal/gas"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
	"github.com/kLauncher1/sheet-license-broker/internal/pqc"
	"github.com/kLauncher1/sheet-license-broker/internal/queue"
	"github.com/kLauncher1/sheet-license-broker/internal/ratelimit"
	"github.com/kLauncher1/sheet-license-broker/internal/replication"
	"github.com/kLauncher1/sheet-license-broker/internal/sso"
	"github.com/kLauncher1/sheet-license-broker/internal/stream"
	"github.com/kLauncher1/sheet-license-broker/internal/tenant"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
	"github.com/kLauncher1/sheet-license-broker/internal/airgap"
	"github.com/kLauncher1/sheet-license-broker/internal/anycast"
	"github.com/kLauncher1/sheet-license-broker/internal/marketplace"
	"github.com/kLauncher1/sheet-license-broker/internal/zerotrust"
	"github.com/kLauncher1/sheet-license-broker/internal/zkp"
)

// Proxy coordinates calls between Google Apps Script, local memory engines, and cache.
type Proxy struct {
	gasClient       *gas.Client
	standbyClient   *gas.Client
	haManager       *replication.HAManager
	spoolQueue      *queue.DiskQueue
	discordAlertURL string
	slackAlertURL   string
	cache           *gas.Cache
	localAuth       *auth.Manager
	localLicense    *license.Manager
	localDB         *db.Storage
	localTenant     *tenant.TenantManager
	featureManager     *feature.Manager
	attestationManager *attestation.Manager
	dispatcher         *webhook.Dispatcher
	rateLimiter        *ratelimit.Limiter
	reputationTracker  *ratelimit.ReputationTracker
	auditCollector     *audit.Collector
	crdtStore          *consensus.CRDTStore
	consensusEngine    *consensus.ConsensusEngine
	p2pMesh            *consensus.P2PMesh
	streamHub          *stream.Hub
	zkpVerifier        *zkp.Verifier
	ssoManager         *sso.Manager
	pqcManager         *pqc.PQCKeyManager
	anomalyEngine      *anomaly.Engine
	enclaveManager     *enclave.Manager
	anycastRouter      *anycast.AnycastRouter
	anycastCache       *anycast.SubMillisecondEdgeCache
	partitionMitigator *anycast.PartitionMitigator
	marketplaceMgr     *marketplace.Manager
	airgapManager      *airgap.Manager
	zeroTrustManager   *zerotrust.ZeroTrustManager
	offlineMode        bool
	cacheTTL           time.Duration
	startTime          time.Time
}

// NewProxy creates a proxy orchestrator. If WebAppURL is empty or OfflineMode is true,
// it uses local in-memory engines.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 10 * time.Minute
	}

	p := &Proxy{
		cache:              gas.NewCache(),
		localAuth:          auth.NewManager(),
		localLicense:       license.NewManager(),
		localDB:            db.NewStorage(),
		localTenant:        tenant.NewTenantManager(),
		featureManager:     feature.NewManager(),
		attestationManager: attestation.NewManager(),
		dispatcher: webhook.NewDispatcher(webhook.Config{
			GlobalWebhookURL: cfg.GlobalWebhookURL,
			GlobalSecret:     cfg.GlobalSecret,
		}),
		rateLimiter:       ratelimit.NewLimiter(ratelimit.DefaultConfig()),
		reputationTracker: ratelimit.NewReputationTracker(ratelimit.DefaultReputationConfig()),
		auditCollector:    audit.NewCollector(5000),
		offlineMode:       cfg.OfflineMode,
		cacheTTL:          cacheTTL,
		startTime:         time.Now(),
		discordAlertURL:   strings.TrimSpace(cfg.DiscordAlertURL),
		slackAlertURL:     strings.TrimSpace(cfg.SlackAlertURL),
	}

	p.initConsensus(cfg)
	p.initStream()
	p.initZKP()
	p.initSSO()
	p.initPQC()
	p.initAnomaly()
	p.initEnclave()
	p.initAnycast(cfg)
	p.initMarketplace(cfg)
	p.initAirGap(cfg)
	p.initZeroTrust(cfg)

	trimmedURL := strings.TrimSpace(cfg.WebAppURL)
	if trimmedURL != "" && !cfg.OfflineMode {
		client, err := gas.NewClient(gas.ClientConfig{
			WebAppURL:   trimmedURL,
			Timeout:     10 * time.Second,
			MaxRetries:  3,
			BackoffBase: 200 * time.Millisecond,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize gas client: %w", err)
		}
		p.gasClient = client
	}

	trimmedStandbyURL := strings.TrimSpace(cfg.StandbyWebAppURL)
	if trimmedStandbyURL != "" && !cfg.OfflineMode {
		standby, err := gas.NewClient(gas.ClientConfig{
			WebAppURL:   trimmedStandbyURL,
			Timeout:     10 * time.Second,
			MaxRetries:  3,
			BackoffBase: 200 * time.Millisecond,
		})
		if err == nil {
			p.standbyClient = standby
		}
	}

	if p.gasClient != nil || p.standbyClient != nil {
		p.haManager = replication.NewHAManager(replication.HAConfig{
			PrimaryClient: p.gasClient,
			StandbyClient: p.standbyClient,
			AutoFailover:  cfg.AutoFailover,
		})
	}

	spoolSecret := []byte(cfg.SpoolSecret)
	if len(spoolSecret) == 0 {
		spoolSecret = []byte("default-sheet-license-broker-spool-key-32b")
	}
	spoolQ, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		FilePath:    cfg.SpoolPath,
		SecretKey:   spoolSecret,
		MaxCapacity: 5000,
	})
	if err == nil {
		p.spoolQueue = spoolQ
	}

	return p, nil
}

// IsRemoteEnabled indicates whether a remote Google Apps Script backend is wired.
func (p *Proxy) IsRemoteEnabled() bool {
	return p.gasClient != nil && !p.offlineMode
}

// WebAppURL returns the configured Apps Script endpoint or empty.
func (p *Proxy) WebAppURL() string {
	if p.gasClient == nil {
		return ""
	}
	return p.gasClient.WebAppURL()
}

// Ping checks remote connectivity if enabled, or confirms local health.
func (p *Proxy) Ping(ctx context.Context) (map[string]interface{}, error) {
	if p.IsRemoteEnabled() {
		res, err := p.gasClient.Ping(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"status":    res.Status,
			"mode":      "remote_gas",
			"message":   res.Message,
			"timestamp": res.Timestamp,
		}, nil
	}

	return map[string]interface{}{
		"status":    "success",
		"mode":      "local_standalone",
		"message":   "Local standalone memory broker active",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// VerifyLicense checks license entitlement with cache and offline fallback.
func (p *Proxy) VerifyLicense(ctx context.Context, key, hwid string) (*VerifyResult, error) {
	key = strings.TrimSpace(key)
	hwid = strings.TrimSpace(hwid)

	// 0. Check local blacklist first
	if err := p.localLicense.Blacklist().Check(key, hwid); err != nil {
		p.cache.DeleteLicense(key)
		return &VerifyResult{
			Valid:      false,
			LicenseKey: key,
			Source:     "blacklist",
			Message:    err.Error(),
		}, err
	}

	// 0b. Check behavioral anomaly quarantine
	if p.anomalyEngine != nil && (p.anomalyEngine.IsQuarantined(key) || p.anomalyEngine.IsQuarantined(hwid)) {
		p.cache.DeleteLicense(key)
		return &VerifyResult{
			Valid:      false,
			LicenseKey: key,
			Source:     "quarantine",
			Message:    "Entity is quarantined due to critical behavioral anomaly",
		}, errors.New("entity is quarantined")
	}

	// 1. Check local cache
	if lic, found, expired := p.cache.GetLicense(key); found && !expired {
		if lic.HWIDBound != "" && hwid != "" && lic.HWIDBound != hwid {
			return &VerifyResult{
				Valid:      false,
				LicenseKey: key,
				Source:     "cache",
				Message:    "Hardware ID mismatch",
			}, ErrLicenseInvalid
		}
		return &VerifyResult{
			Valid:      true,
			LicenseKey: key,
			HWIDBound:  lic.HWIDBound,
			ExpiresAt:  lic.ExpiresAt,
			Source:     "cache",
			Message:    "Verified from local cache",
		}, nil
	}

	// 2. Query remote Google Apps Script if enabled
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.VerifyLicense(ctx, key, hwid)
		if resp != nil && (resp.Blacklisted || resp.Revoked) {
			p.cache.DeleteLicense(key)
			p.localLicense.Blacklist().Add(license.BlacklistTypeLicense, key, resp.Message)
			return &VerifyResult{
				Valid:      false,
				LicenseKey: key,
				Source:     "remote_blacklist",
				Message:    resp.Message,
			}, fmt.Errorf("license verification rejected: %s", resp.Message)
		}
		if err == nil && resp.Verified {
			p.cache.SetLicense(key, resp, p.cacheTTL)
			tier := resp.Tier
			if tier == "" {
				tier = "pro"
			}
			feats := resp.Features
			if len(feats) == 0 {
				_, feats = p.featureManager.GetEffectiveFeatures(key, feature.NormalizeTier(tier))
			}
			return &VerifyResult{
				Valid:      true,
				LicenseKey: key,
				HWIDBound:  resp.HWIDBound,
				ExpiresAt:  resp.ExpiresAt,
				Tier:       tier,
				Features:   feats,
				Source:     "remote_gas",
				Message:    resp.Message,
			}, nil
		}

		// On remote failure (rate limit, timeout, network error), attempt offline fallback
		log.Printf("[Proxy] Remote verification failed (%v), checking offline fallback...", err)
		if lic, found, expired := p.cache.GetLicense(key); found {
			source := "offline_cache"
			if expired {
				source = "offline_cache_expired_grace"
			}
			tier, feats := p.featureManager.GetEffectiveFeatures(key, feature.TierPro)
			return &VerifyResult{
				Valid:      true,
				LicenseKey: key,
				HWIDBound:  lic.HWIDBound,
				ExpiresAt:  lic.ExpiresAt,
				Tier:       string(tier),
				Features:   feats,
				Source:     source,
				Message:    "Served via offline grace cache during remote outage",
			}, nil
		}
	}

	// 3. Fallback to local in-memory engine
	lic, err := p.localLicense.VerifyAndBind(key, hwid)
	if err != nil {
		return nil, err
	}

	tier, feats := p.featureManager.GetEffectiveFeatures(lic.LicenseKey, feature.NormalizeTier(lic.Tier))
	return &VerifyResult{
		Valid:      true,
		LicenseKey: lic.LicenseKey,
		HWIDBound:  lic.BoundHWID,
		ExpiresAt:  lic.ExpiresAt.Format(time.RFC3339),
		Tier:       string(tier),
		Features:   feats,
		Source:     "local_fallback",
		Message:    "Verified against local memory database",
	}, nil
}

// CreateLicense generates a new license key in remote GAS or local store.
func (p *Proxy) CreateLicense(ctx context.Context, days, maxDevices int) (*LicenseResult, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.CreateLicense(ctx, "", days, maxDevices)
		if err == nil {
			tier := resp.Tier
			if tier == "" {
				tier = "pro"
			}
			feats := resp.Features
			if len(feats) == 0 {
				_, feats = p.featureManager.GetEffectiveFeatures(resp.LicenseKey, feature.NormalizeTier(tier))
			}
			return &LicenseResult{
				LicenseKey: resp.LicenseKey,
				ExpiresAt:  resp.ExpiresAt,
				Status:     resp.Status,
				Tier:       tier,
				Features:   feats,
				Source:     "remote_gas",
			}, nil
		}
		log.Printf("[Proxy] Remote license creation failed: %v. Falling back to local store.", err)
	}

	lic := p.localLicense.CreateLicense(days, maxDevices)
	tier, feats := p.featureManager.GetEffectiveFeatures(lic.LicenseKey, feature.NormalizeTier(lic.Tier))
	return &LicenseResult{
		LicenseKey: lic.LicenseKey,
		ExpiresAt:  lic.ExpiresAt.Format(time.RFC3339),
		Status:     lic.Status,
		Tier:       string(tier),
		Features:   feats,
		Source:     "local_fallback",
	}, nil
}

// CreateLicenseWithTier generates a new license key with custom tier and features in remote GAS or local store.
func (p *Proxy) CreateLicenseWithTier(ctx context.Context, days, maxDevices int, tier string, features []string) (*LicenseResult, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.CreateLicense(ctx, "", days, maxDevices)
		if err == nil {
			tVal := tier
			if tVal == "" {
				tVal = resp.Tier
			}
			if tVal == "" {
				tVal = "pro"
			}
			feats := features
			if len(feats) == 0 {
				feats = resp.Features
			}
			if len(feats) == 0 {
				_, feats = p.featureManager.GetEffectiveFeatures(resp.LicenseKey, feature.NormalizeTier(tVal))
			}
			return &LicenseResult{
				LicenseKey: resp.LicenseKey,
				ExpiresAt:  resp.ExpiresAt,
				Status:     resp.Status,
				Tier:       tVal,
				Features:   feats,
				Source:     "remote_gas",
			}, nil
		}
		log.Printf("[Proxy] Remote license creation failed: %v. Falling back to local store.", err)
	}

	lic := p.localLicense.CreateLicenseWithTier(days, maxDevices, tier, features)
	effTier, feats := p.featureManager.GetEffectiveFeatures(lic.LicenseKey, feature.NormalizeTier(lic.Tier))
	return &LicenseResult{
		LicenseKey: lic.LicenseKey,
		ExpiresAt:  lic.ExpiresAt.Format(time.RFC3339),
		Status:     lic.Status,
		Tier:       string(effTier),
		Features:   feats,
		Source:     "local_fallback",
	}, nil
}

// RegisterUser registers a user via remote GAS or local engine.
func (p *Proxy) RegisterUser(ctx context.Context, username, password, role string) (*auth.User, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.RegisterUser(ctx, username, password)
		if err == nil {
			return &auth.User{
				UserID:   resp.UserID,
				Username: resp.Username,
				Role:     role,
			}, nil
		}
		log.Printf("[Proxy] Remote registration failed: %v. Falling back to local engine.", err)
	}

	return p.localAuth.RegisterUser(username, password, role)
}

// AuthenticateUser verifies user credentials against remote GAS or local store.
func (p *Proxy) AuthenticateUser(ctx context.Context, username, password string) (*auth.User, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.LoginUser(ctx, username, password)
		if err == nil {
			return &auth.User{
				UserID:   resp.UserID,
				Username: resp.Username,
				Role:     resp.Role,
			}, nil
		}
		return nil, ErrInvalidCredentials
	}

	return p.localAuth.Authenticate(username, password)
}

// PutDocument stores a document in remote GAS or local store with cache update.
func (p *Proxy) PutDocument(ctx context.Context, collection, docID, payload string) (*db.Document, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.PutDocument(ctx, collection, docID, payload)
		if err == nil {
			p.cache.SetDoc(collection, docID, resp, p.cacheTTL)
			return &db.Document{
				Collection: collection,
				DocID:      docID,
				Payload:    payload,
				UpdatedAt:  time.Now(),
			}, nil
		}
		log.Printf("[Proxy] Remote PutDocument failed: %v. Storing locally.", err)
	}

	return p.localDB.Put(collection, docID, payload), nil
}

// GetDocument retrieves a document by collection and ID.
func (p *Proxy) GetDocument(ctx context.Context, collection, docID string) (*db.Document, error) {
	// 1. Check local cache
	if cached, found, _ := p.cache.GetDoc(collection, docID); found {
		return &db.Document{
			Collection: collection,
			DocID:      docID,
			Payload:    fmt.Sprintf("%v", cached.Data),
			UpdatedAt:  time.Now(),
		}, nil
	}

	// 2. Remote GAS
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.GetDocument(ctx, collection, docID)
		if err == nil {
			p.cache.SetDoc(collection, docID, resp, p.cacheTTL)
			return &db.Document{
				Collection: collection,
				DocID:      docID,
				Payload:    fmt.Sprintf("%v", resp.Data),
				UpdatedAt:  time.Now(),
			}, nil
		}
	}

	// 3. Local DB
	return p.localDB.Get(collection, docID)
}

// ListLicenses returns cached or local licenses for UI presentation.
func (p *Proxy) ListLicenses() []license.License { return p.localLicense.ListLicenses() }

// ListUsers returns local users for UI presentation.
func (p *Proxy) ListUsers() []auth.User { return p.localAuth.ListUsers() }

// ListDocuments returns all local documents.
func (p *Proxy) ListDocuments() []db.Document { return p.localDB.ListAll() }

// Status delivers diagnostic metrics on proxy state.
func (p *Proxy) Status() map[string]interface{} {
	mode := "local_standalone"
	if p.IsRemoteEnabled() {
		mode = "remote_gas_proxy"
	} else if p.offlineMode {
		mode = "offline_forced"
	}

	return map[string]interface{}{
		"mode":             mode,
		"remote_enabled":   p.IsRemoteEnabled(),
		"webapp_url":       p.WebAppURL(),
		"cache_entries":    p.cache.Len(),
		"cache_ttl":        p.cacheTTL.String(),
		"uptime_seconds":   int(time.Since(p.startTime).Seconds()),
	}
}
