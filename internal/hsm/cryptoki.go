package hsm

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrSlotNotFound         = errors.New("hsm: slot not found")
	ErrSessionInvalid       = errors.New("hsm: session handle invalid")
	ErrPINIncorrect         = errors.New("hsm: pin incorrect")
	ErrPINLocked            = errors.New("hsm: pin locked due to excessive failed attempts")
	ErrUnauthorized         = errors.New("hsm: session unauthorized for operation")
	ErrObjectNotFound       = errors.New("hsm: object handle not found")
	ErrTamperDetected       = errors.New("hsm: tamper event latched, hardware locked")
	ErrZeroized             = errors.New("hsm: hardware cryptographic storage has been zeroized")
)

// CryptokiSlot represents a physical or emulated PKCS#11 cryptographic slot.
type CryptokiSlot struct {
	mu             sync.RWMutex
	info           SlotInfo
	token          TokenInfo
	userPIN        []byte
	soPIN          []byte
	failedAttempts int
	maxAttempts    int
	masterSeed     []byte
	objects        map[uint64]*CryptokiObject
	nextObjHandle  uint64
	zeroized       bool
	tampered       bool
}

// CryptokiObject encapsulates a hardware-bound cryptographic key or certificate.
type CryptokiObject struct {
	Handle      uint64
	Class       uint32
	KeyType     uint32
	Label       string
	Extractable bool
	Sensitive   bool
	TokenObject bool
	SecretBytes []byte
	PubPEM      string
	Fingerprint string
	CreatedAt   time.Time
}

// CryptokiSession models an open connection to a token within a slot.
type CryptokiSession struct {
	Handle     uint64
	SlotID     int
	State      string
	UserType   string
	CreatedAt  time.Time
	LastAccess time.Time
}

// CryptokiEngine orchestrates the PKCS#11 runtime, slots, sessions, and object lifecycle.
type CryptokiEngine struct {
	mu             sync.RWMutex
	slots          map[int]*CryptokiSlot
	sessions       map[uint64]*CryptokiSession
	nextSessionID  uint64
	opsCount       int64
	tamperLatched  bool
	startTime      time.Time
}

// NewCryptokiEngine initializes a multi-slot FIPS 140-3 Level 4 Cryptoki engine.
func NewCryptokiEngine() (*CryptokiEngine, error) {
	engine := &CryptokiEngine{
		slots:         make(map[int]*CryptokiSlot),
		sessions:      make(map[uint64]*CryptokiSession),
		nextSessionID: 1000,
		startTime:     time.Now(),
	}

	// Slot 0: Root Master Vault
	if err := engine.initSlot(0, "HSM-FIPS-ROOT-TOKEN", "HSM4-ROOT-9842", "FIPS-ROOT-PIN-9842", "SO-ROOT-ADMIN-0000"); err != nil {
		return nil, fmt.Errorf("failed to init slot 0: %w", err)
	}

	// Slot 1: Audit & Snapshot Encryption Vault
	if err := engine.initSlot(1, "HSM-AUDIT-SNAPSHOT-VAULT", "HSM4-SNAP-1102", "FIPS-SNAP-PIN-1102", "SO-SNAP-ADMIN-0000"); err != nil {
		return nil, fmt.Errorf("failed to init slot 1: %w", err)
	}

	// Slot 2: Multi-Tenant Key Derivation Vault
	if err := engine.initSlot(2, "HSM-TENANT-DERIVATION-VAULT", "HSM4-TENANT-3398", "FIPS-TENANT-PIN-3398", "SO-TENANT-ADMIN-0000"); err != nil {
		return nil, fmt.Errorf("failed to init slot 2: %w", err)
	}

	return engine, nil
}

func (e *CryptokiEngine) initSlot(slotID int, label, serial, userPin, soPin string) error {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}

	slot := &CryptokiSlot{
		info: SlotInfo{
			SlotID:          slotID,
			Description:     fmt.Sprintf("Hardware HSM Cryptoki Slot %d", slotID),
			ManufacturerID:  "CloudHSM Cryptoki Enterprise Inc.",
			HardwareVersion: "4.2.0",
			FirmwareVersion: "4.2.0-FIPS",
			Mechanisms: []string{
				"CKM_AES_GCM", "CKM_HKDF_DERIVE", "CKM_ECDSA", "CKM_SHA256_HMAC", "CKM_GENERIC_SECRET_KEY_GEN",
			},
			TokenPresent: true,
			Removable:    false,
			HardwareSlot: true,
		},
		token: TokenInfo{
			SlotID:             slotID,
			Label:              label,
			ManufacturerID:     "CloudHSM Cryptoki Enterprise Inc.",
			Model:              "FIPS-140-3-L4-VAULT",
			SerialNumber:       serial,
			MaxSessionCount:    128,
			SessionCount:       0,
			MaxPinLen:          64,
			MinPinLen:          8,
			TotalPrivateMemory: 65536,
			FreePrivateMemory:  64512,
			FIPSLevel:          FIPSLevel4,
			UserPinInitialized: true,
			UserPinLocked:      false,
			SOPinLocked:        false,
			TamperDetected:     false,
			InitializedAt:      time.Now(),
		},
		userPIN:        []byte(userPin),
		soPIN:          []byte(soPin),
		failedAttempts: 0,
		maxAttempts:    5,
		masterSeed:     seed,
		objects:        make(map[uint64]*CryptokiObject),
		nextObjHandle:  1,
	}

	// Seed pre-provisioned persistent master object in slot
	slot.objects[1] = &CryptokiObject{
		Handle:      1,
		Class:       CKO_SECRET_KEY,
		KeyType:     CKK_GENERIC_SECRET,
		Label:       fmt.Sprintf("%s-MASTER-KEY", label),
		Extractable: false,
		Sensitive:   true,
		TokenObject: true,
		SecretBytes: append([]byte(nil), seed...),
		Fingerprint: fmt.Sprintf("FPR-%s-01", serial),
		CreatedAt:   time.Now(),
	}
	slot.nextObjHandle = 2

	e.slots[slotID] = slot
	return nil
}

// OpenSession creates a new session in the specified slot.
func (e *CryptokiEngine) OpenSession(slotID int) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.tamperLatched {
		return 0, ErrTamperDetected
	}

	slot, ok := e.slots[slotID]
	if !ok {
		return 0, ErrSlotNotFound
	}

	slot.mu.Lock()
	defer slot.mu.Unlock()

	if slot.zeroized {
		return 0, ErrZeroized
	}
	if slot.tampered {
		return 0, ErrTamperDetected
	}

	handle := atomic.AddUint64(&e.nextSessionID, 1)
	session := &CryptokiSession{
		Handle:     handle,
		SlotID:     slotID,
		State:      CKS_RO_PUBLIC_SESSION,
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
	}

	e.sessions[handle] = session
	slot.token.SessionCount = len(e.sessions)
	atomic.AddInt64(&e.opsCount, 1)

	return handle, nil
}

// CloseSession terminates an active session.
func (e *CryptokiEngine) CloseSession(handle uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	sess, ok := e.sessions[handle]
	if !ok {
		return ErrSessionInvalid
	}

	if slot, exists := e.slots[sess.SlotID]; exists {
		slot.mu.Lock()
		if slot.token.SessionCount > 0 {
			slot.token.SessionCount--
		}
		slot.mu.Unlock()
	}

	delete(e.sessions, handle)
	return nil
}

// Login authenticates a session with User or Security Officer PIN.
func (e *CryptokiEngine) Login(handle uint64, userType uint32, pin string) error {
	e.mu.Lock()
	sess, ok := e.sessions[handle]
	if !ok {
		e.mu.Unlock()
		return ErrSessionInvalid
	}
	slot, exists := e.slots[sess.SlotID]
	e.mu.Unlock()

	if !exists {
		return ErrSlotNotFound
	}

	slot.mu.Lock()
	defer slot.mu.Unlock()

	if slot.zeroized {
		return ErrZeroized
	}
	if slot.tampered {
		return ErrTamperDetected
	}
	if slot.token.UserPinLocked || (userType == CKU_SO && slot.token.SOPinLocked) {
		return ErrPINLocked
	}

	var expectedPIN []byte
	var targetState string
	var uTypeStr string

	if userType == CKU_SO {
		expectedPIN = slot.soPIN
		targetState = CKS_RW_SO_FUNCTIONS
		uTypeStr = "SO"
	} else {
		expectedPIN = slot.userPIN
		targetState = CKS_RW_USER_FUNCTIONS
		uTypeStr = "USER"
	}

	// Constant-time PIN comparison
	pinBytes := []byte(pin)
	if subtle.ConstantTimeCompare(pinBytes, expectedPIN) != 1 {
		slot.failedAttempts++
		if slot.failedAttempts >= slot.maxAttempts {
			slot.token.UserPinLocked = true
			if userType == CKU_SO {
				slot.token.SOPinLocked = true
			}
			return ErrPINLocked
		}
		return ErrPINIncorrect
	}

	// Successful login resets failure counter
	slot.failedAttempts = 0
	sess.State = targetState
	sess.UserType = uTypeStr
	sess.LastAccess = time.Now()

	atomic.AddInt64(&e.opsCount, 1)
	return nil
}

// Logout downgrades the session back to public state.
func (e *CryptokiEngine) Logout(handle uint64) error {
	e.mu.Lock()
	sess, ok := e.sessions[handle]
	e.mu.Unlock()

	if !ok {
		return ErrSessionInvalid
	}

	sess.State = CKS_RO_PUBLIC_SESSION
	sess.UserType = ""
	sess.LastAccess = time.Now()
	return nil
}

// ListSlots returns public descriptors for all provisioned slots.
func (e *CryptokiEngine) ListSlots() []SlotInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	slots := make([]SlotInfo, 0, len(e.slots))
	for i := 0; i < len(e.slots); i++ {
		if s, ok := e.slots[i]; ok {
			s.mu.RLock()
			slots = append(slots, s.info)
			s.mu.RUnlock()
		}
	}
	return slots
}

// GetTokenInfo retrieves token metadata for a slot.
func (e *CryptokiEngine) GetTokenInfo(slotID int) (*TokenInfo, error) {
	e.mu.RLock()
	slot, ok := e.slots[slotID]
	e.mu.RUnlock()

	if !ok {
		return nil, ErrSlotNotFound
	}

	slot.mu.RLock()
	defer slot.mu.RUnlock()

	info := slot.token
	return &info, nil
}

// GetMasterSeed returns the hardware master secret bytes for internal derivation.
func (e *CryptokiEngine) GetMasterSeed(slotID int) ([]byte, error) {
	e.mu.RLock()
	slot, ok := e.slots[slotID]
	e.mu.RUnlock()

	if !ok {
		return nil, ErrSlotNotFound
	}

	slot.mu.RLock()
	defer slot.mu.RUnlock()

	if slot.zeroized {
		return nil, ErrZeroized
	}
	if slot.tampered || e.tamperLatched {
		return nil, ErrTamperDetected
	}

	out := make([]byte, len(slot.masterSeed))
	copy(out, slot.masterSeed)
	return out, nil
}

// Zeroize wipes all slot secrets, sessions, and memory with cryptographic zeroes.
func (e *CryptokiEngine) Zeroize() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, slot := range e.slots {
		slot.mu.Lock()
		for i := range slot.masterSeed {
			slot.masterSeed[i] = 0
		}
		for i := range slot.userPIN {
			slot.userPIN[i] = 0
		}
		for i := range slot.soPIN {
			slot.soPIN[i] = 0
		}
		for _, obj := range slot.objects {
			for i := range obj.SecretBytes {
				obj.SecretBytes[i] = 0
			}
			obj.SecretBytes = nil
		}
		slot.objects = make(map[uint64]*CryptokiObject)
		slot.zeroized = true
		slot.token.FreePrivateMemory = 0
		slot.mu.Unlock()
	}

	e.sessions = make(map[uint64]*CryptokiSession)
}

// LatchTamper simulates physical tamper detection, triggering immediate zeroization.
func (e *CryptokiEngine) LatchTamper() {
	e.mu.Lock()
	e.tamperLatched = true
	for _, slot := range e.slots {
		slot.mu.Lock()
		slot.tampered = true
		slot.token.TamperDetected = true
		slot.mu.Unlock()
	}
	e.mu.Unlock()

	// Zeroize all cryptographic boundaries immediately
	e.Zeroize()
}

// RecordOp increments the cryptographic operations counter.
func (e *CryptokiEngine) RecordOp() {
	atomic.AddInt64(&e.opsCount, 1)
}

// OperationsCount returns total cryptographic operations performed by the engine.
func (e *CryptokiEngine) OperationsCount() int64 {
	return atomic.LoadInt64(&e.opsCount)
}

// ActiveSessionCount returns the number of open sessions.
func (e *CryptokiEngine) ActiveSessionCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.sessions)
}
