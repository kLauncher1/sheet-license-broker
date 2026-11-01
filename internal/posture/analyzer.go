package posture

import (
	"math"
	"strings"
	"time"
)

// PolicyConfig configures weights, thresholds, and gating requirements for posture scoring.
type PolicyConfig struct {
	OSWeight           float64 `json:"os_weight"`
	HardwareWeight     float64 `json:"hardware_weight"`
	EndpointWeight     float64 `json:"endpoint_weight"`
	IntegrityWeight    float64 `json:"integrity_weight"`
	MaxPatchAgeDays    int     `json:"max_patch_age_days"`
	MaxAVDefAgeDays    int     `json:"max_av_def_age_days"`
	RequireSecureBoot  bool    `json:"require_secure_boot"`
	RequireTPM         bool    `json:"require_tpm"`
	RequireDiskCrypto  bool    `json:"require_disk_crypto"`
	RequireFirewall    bool    `json:"require_firewall"`
	EnforceIntegrity   bool    `json:"enforce_integrity"`
}

// DefaultPolicyConfig returns balanced zero-trust posture evaluation weights and thresholds.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		OSWeight:          0.25,
		HardwareWeight:    0.25,
		EndpointWeight:    0.30,
		IntegrityWeight:   0.20,
		MaxPatchAgeDays:   30,
		MaxAVDefAgeDays:   7,
		RequireSecureBoot: true,
		RequireTPM:        true,
		RequireDiskCrypto: true,
		RequireFirewall:   true,
		EnforceIntegrity:  true,
	}
}

// AnalyzePosture evaluates raw device posture telemetry against policy invariants.
func AnalyzePosture(report DevicePostureReport, policy PolicyConfig) PostureVectorScores {
	var violations []string
	var remediations []string

	// 1. Evaluate OS & Patch Vector
	osScore := 100.0
	if strings.TrimSpace(report.OS.OSName) == "" || strings.TrimSpace(report.OS.OSVersion) == "" {
		osScore -= 20.0
		violations = append(violations, "Unidentified operating system or version string")
		remediations = append(remediations, "Provide valid OS name and build metadata")
	}

	patchDays := report.OS.PatchLevelDays
	if patchDays < 0 {
		patchDays = 0
	}

	if patchDays > 90 {
		osScore -= 70.0
		violations = append(violations, "OS security patch level critically outdated (>90 days)")
		remediations = append(remediations, "Apply urgent cumulative OS security updates")
	} else if patchDays > 60 {
		osScore -= 40.0
		violations = append(violations, "OS security patch level overdue (>60 days)")
		remediations = append(remediations, "Install pending operating system security updates")
	} else if patchDays > policy.MaxPatchAgeDays {
		osScore -= 20.0
		violations = append(violations, "OS security patch older than policy limit (>30 days)")
		remediations = append(remediations, "Check for and apply monthly OS security rollups")
	} else if patchDays > 14 {
		osScore -= 10.0
	}
	if osScore < 0.0 {
		osScore = 0.0
	}

	// 2. Evaluate Hardware & Boot Security Vector
	hwScore := 0.0
	if report.Hardware.SecureBootEnabled {
		hwScore += 35.0
	} else {
		if policy.RequireSecureBoot {
			violations = append(violations, "UEFI Secure Boot is disabled")
			remediations = append(remediations, "Enable Secure Boot in system firmware / UEFI settings")
		}
	}

	if report.Hardware.TPMPresent {
		tpmVer := strings.TrimSpace(report.Hardware.TPMVersion)
		if strings.HasPrefix(tpmVer, "2") {
			hwScore += 35.0
		} else if strings.HasPrefix(tpmVer, "1.2") {
			hwScore += 20.0
			violations = append(violations, "Legacy TPM 1.2 chip detected; TPM 2.0 recommended")
		} else {
			hwScore += 25.0
		}
	} else {
		if policy.RequireTPM {
			violations = append(violations, "Cryptographic TPM hardware is not detected or enabled")
			remediations = append(remediations, "Enable firmware TPM (fTPM/PTT) or install discrete TPM 2.0 module")
		}
	}

	if report.Hardware.DiskEncryptionActive {
		hwScore += 30.0
	} else {
		if policy.RequireDiskCrypto {
			violations = append(violations, "Full-disk encryption (BitLocker / FileVault / LUKS) is inactive")
			remediations = append(remediations, "Activate full-disk volume encryption on boot partitions")
		}
	}
	if hwScore > 100.0 {
		hwScore = 100.0
	}

	// 3. Evaluate Endpoint & AV Defense Vector
	epScore := 0.0
	if report.Endpoint.AntivirusActive {
		epScore += 35.0
		defDays := report.Endpoint.DefinitionsAgeDays
		if defDays <= 3 {
			epScore += 25.0
		} else if defDays <= policy.MaxAVDefAgeDays {
			epScore += 15.0
		} else {
			violations = append(violations, "Antivirus virus definitions are stale (>7 days)")
			remediations = append(remediations, "Trigger immediate anti-malware signature update")
		}
	} else {
		violations = append(violations, "Endpoint anti-malware service is disabled or uninstalled")
		remediations = append(remediations, "Enable and start host antivirus / EDR sensor")
	}

	if report.Endpoint.RealtimeProtection {
		epScore += 20.0
	} else {
		violations = append(violations, "Antivirus real-time behavioural protection is switched off")
		remediations = append(remediations, "Turn on real-time filesystem scanning in antivirus settings")
	}

	if report.Endpoint.FirewallEnabled {
		epScore += 20.0
	} else {
		if policy.RequireFirewall {
			violations = append(violations, "Local endpoint host firewall is inactive")
			remediations = append(remediations, "Enable system firewall and block unrequested incoming traffic")
		}
	}
	if epScore > 100.0 {
		epScore = 100.0
	}

	// 4. Evaluate Runtime Integrity Vector
	intScore := 0.0
	criticalIntegrityTrip := false

	if report.Integrity.DebuggerAttached {
		criticalIntegrityTrip = true
		violations = append(violations, "Active process debugger or memory tracing tool detected")
		remediations = append(remediations, "Detach debuggers and disengage analysis hooks")
	}
	if report.Integrity.RootedOrJailbroken {
		criticalIntegrityTrip = true
		violations = append(violations, "Host operating system root / jailbreak bypass detected")
		remediations = append(remediations, "Restore device firmware to official unrooted release")
	}

	if report.Integrity.CodeIntegrityVerified {
		intScore += 60.0
	} else {
		intScore += 20.0
		violations = append(violations, "Client code signing / binary integrity check unverified")
		remediations = append(remediations, "Reinstall authenticated client software package")
	}

	if !report.Integrity.VirtualizationDetected {
		intScore += 40.0
	} else {
		intScore += 25.0
	}

	if criticalIntegrityTrip {
		intScore = 0.0
	} else if intScore > 100.0 {
		intScore = 100.0
	}

	// Compute composite weighted confidence score
	composite := (osScore * policy.OSWeight) +
		(hwScore * policy.HardwareWeight) +
		(epScore * policy.EndpointWeight) +
		(intScore * policy.IntegrityWeight)

	composite = math.Round(composite*10.0) / 10.0
	if composite < 0.0 {
		composite = 0.0
	} else if composite > 100.0 {
		composite = 100.0
	}

	// Determine posture tier and gating actions
	tier := PostureTierHealthy
	degradedAllowed := false

	if criticalIntegrityTrip {
		tier = PostureTierQuarantine
		degradedAllowed = false
	} else if !report.Endpoint.AntivirusActive && !report.Endpoint.FirewallEnabled {
		tier = PostureTierQuarantine
		violations = append(violations, "Total failure of host network and malware defenses")
		degradedAllowed = false
	} else if composite < 60.0 {
		tier = PostureTierQuarantine
		// Low score without active compromise can degrade gracefully to read-only heartbeat
		if composite >= 35.0 {
			degradedAllowed = true
		}
	} else if composite < 80.0 {
		tier = PostureTierWarning
		degradedAllowed = true
	} else {
		tier = PostureTierHealthy
		degradedAllowed = false
	}

	return PostureVectorScores{
		DeviceID:            report.DeviceID,
		TenantID:            report.TenantID,
		OSScore:             osScore,
		HardwareScore:       hwScore,
		EndpointScore:       epScore,
		IntegrityScore:      intScore,
		CompositeScore:      composite,
		Tier:                tier,
		Violations:          violations,
		Remediations:        remediations,
		DegradedModeAllowed: degradedAllowed,
		EvaluatedAt:         time.Now().UTC(),
	}
}
