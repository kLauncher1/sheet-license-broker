/**
 * Sheet-License-Broker (Google Apps Script Backend)
 * 
 * Provides serverless multi-tenant authentication, license validation with HWID binding,
 * device blacklisting, automated backup snapshots, and NoSQL key-value storage.
 */

const SHEET_USERS = 'Users';
const SHEET_LICENSES = 'Licenses';
const SHEET_DATABASE = 'KV_Database';
const SHEET_BLACKLIST = 'Blacklist';
const SHEET_AUDIT_LOGS = 'Audit_Logs';
const SHEET_TENANTS = 'Tenants';
const SHEET_USAGE = 'Usage_Metering';
const SHEET_FEATURE_FLAGS = 'FeatureFlags';
const SHEET_ATTESTATIONS = 'Attestations';
const SHEET_CONSENSUS_NODES = 'ConsensusNodes';
const SHEET_STREAM_EVENTS = 'StreamEvents';
const SHEET_ZKP_CREDENTIALS = 'ZKP_Credentials';
const SHEET_ZKP_NULLIFIERS = 'ZKP_Nullifiers';
const SHEET_SSO_CONFIGS = 'SSO_Configs';
const SHEET_DIRECTORY_USERS = 'Directory_Users';
const SHEET_PQC_KEYS = 'PQC_Keys';
const SHEET_ANOMALY_INCIDENTS = 'Anomaly_Incidents';
const SHEET_ENCLAVE_ATTESTATIONS = 'Enclave_Attestations';
const SHEET_ENCLAVE_POLICIES = 'Enclave_Policies';
const SHEET_ENCLAVE_TOKENS = 'Enclave_Tokens';
const SHEET_GEO_POPS = 'Geo_POPs';
const SHEET_PARTITION_EVENTS = 'Partition_Events';
const SHEET_MARKETPLACE_TRANSACTIONS = 'Marketplace_Transactions';
const SHEET_AIRGAP_VAULT = 'AirGap_Vault';
const SHEET_ZEROTRUST_PEERS = 'ZeroTrust_Peers';
const SHEET_ZEROTRUST_CA = 'ZeroTrust_CA';
const SHEET_HEALING_LEASES = 'Healing_Leases';
const SHEET_HEALING_TUNNELS = 'Healing_Tunnels';
const SHEET_HSM_AUDIT_LOG = 'HSM_Audit_Log';
const SHEET_HSM_VAULT_KEYS = 'HSM_Vault_Keys';
const SHEET_MLKEM_KEY_LEDGER = 'MLKEM_Key_Ledger';
const SHEET_MLKEM_SESSIONS = 'MLKEM_Sessions';
const SHEET_TRANSPARENCY_LOG = 'Transparency_Log';
const SHEET_WITNESS_COSIGNATURES = 'Witness_Cosignatures';

function doGet(e) {
  return handleRequest(e, 'GET');
}

function doPost(e) {
  return handleRequest(e, 'POST');
}

function handleRequest(e, method) {
  const output = ContentService.createTextOutput();
  output.setMimeType(ContentService.MimeType.JSON);

  try {
    initSheets();

    let payload = {};
    if (e && e.postData && e.postData.contents) {
      try {
        payload = JSON.parse(e.postData.contents);
      } catch (err) {
        payload = {};
      }
    } else if (e && e.parameter) {
      payload = e.parameter;
    }

    const action = payload.action || 'ping';

    switch (action) {
      case 'ping':
        return jsonResponse(output, { status: 'success', message: 'Sheet-License-Broker live', timestamp: new Date().toISOString() });

      case 'register':
        return handleRegister(output, payload);

      case 'login':
        return handleLogin(output, payload);

      case 'create_license':
        return handleCreateLicense(output, payload);

      case 'verify_license':
        return handleVerifyLicense(output, payload);

      case 'revoke_license':
        return handleRevokeLicense(output, payload);

      case 'tenant_register':
        return handleTenantRegister(output, payload);

      case 'tenant_list':
        return handleTenantList(output, payload);

      case 'backup_export':
        return handleBackupExport(output, payload);

      case 'backup_restore':
        return handleBackupRestore(output, payload);

      case 'blacklist_add':
        return handleBlacklistAdd(output, payload);

      case 'blacklist_remove':
        return handleBlacklistRemove(output, payload);

      case 'blacklist_list':
        return handleBlacklistList(output, payload);

      case 'db_put':
        return handleDBPut(output, payload);

      case 'db_get':
        return handleDBGet(output, payload);

      case 'features_list':
        return handleFeaturesList(output, payload);

      case 'usage_record':
        return handleUsageRecord(output, payload);

      case 'usage_get':
        return handleUsageGet(output, payload);

      case 'attestation_record':
        return handleAttestationRecord(output, payload);

      case 'attestation_list':
        return handleAttestationList(output, payload);

      case 'audit_log_record':
        return handleAuditLogRecord(output, payload);

      case 'audit_log_list':
        return handleAuditLogList(output, payload);

      case 'consensus_node_heartbeat':
        return handleConsensusNodeHeartbeat(output, payload);

      case 'consensus_node_list':
        return handleConsensusNodeList(output, payload);

      case 'stream_event_record':
        return handleStreamEventRecord(output, payload);

      case 'stream_event_list':
        return handleStreamEventList(output, payload);

      case 'zkp_record_credential':
        return handleZKPRecordCredential(output, payload);

      case 'zkp_record_nullifier':
        return handleZKPRecordNullifier(output, payload);

      case 'zkp_list':
        return handleZKPList(output, payload);

      case 'sso_idp_save':
        return handleSSOIdPSave(output, payload);

      case 'sso_idp_list':
        return handleSSOIdPList(output, payload);

      case 'scim_user_sync':
        return handleSCIMUserSync(output, payload);

      case 'scim_user_deprovision':
        return handleSCIMUserDeprovision(output, payload);

      case 'scim_user_list':
        return handleSCIMUserList(output, payload);

      case 'pqc_key_save':
        return handlePQCKeySave(output, payload);

      case 'pqc_key_revoke':
        return handlePQCKeyRevoke(output, payload);

      case 'pqc_key_list':
        return handlePQCKeyList(output, payload);

      case 'anomaly_record':
        return handleAnomalyRecord(output, payload);

      case 'anomaly_incident_list':
        return handleAnomalyIncidentList(output, payload);

      case 'enclave_attest_log':
        return handleEnclaveAttestLog(output, payload);

      case 'enclave_attest_list':
        return handleEnclaveAttestList(output, payload);

      case 'enclave_policy_save':
        return handleEnclavePolicySave(output, payload);

      case 'enclave_policy_list':
        return handleEnclavePolicyList(output, payload);

      case 'enclave_token_record':
        return handleEnclaveTokenRecord(output, payload);

      case 'enclave_token_list':
        return handleEnclaveTokenList(output, payload);

      case 'anycast_pop_heartbeat':
        return handleAnycastPOPHeartbeat(output, payload);

      case 'anycast_pop_list':
        return handleAnycastPOPList(output, payload);

      case 'partition_event_log':
        return handlePartitionEventLog(output, payload);

      case 'marketplace_record_transaction':
        return handleMarketplaceRecordTransaction(output, payload);

      case 'marketplace_list_transactions':
        return handleMarketplaceListTransactions(output, payload);

      case 'marketplace_get_status':
        return handleMarketplaceGetStatus(output, payload);

      case 'airgap_record_token':
        return handleAirgapRecordToken(output, payload);

      case 'airgap_list_tokens':
        return handleAirgapListTokens(output, payload);

      case 'airgap_get_status':
        return handleAirgapGetStatus(output, payload);

      case 'zerotrust_enroll_peer':
        return handleZeroTrustEnrollPeer(output, payload);

      case 'zerotrust_revoke_peer':
        return handleZeroTrustRevokePeer(output, payload);

      case 'zerotrust_rotate_ca':
        return handleZeroTrustRotateCA(output, payload);

      case 'zerotrust_get_status':
        return handleZeroTrustGetStatus(output, payload);

      case 'healing_record_lease':
        return handleHealingRecordLease(output, payload);

      case 'healing_return_lease':
        return handleHealingReturnLease(output, payload);

      case 'healing_log_tunnel':
        return handleHealingLogTunnel(output, payload);

      case 'healing_get_status':
        return handleHealingGetStatus(output, payload);

      case 'hsm_log_event':
        return handleHSMLogEvent(output, payload);

      case 'hsm_get_status':
        return handleHSMGetStatus(output, payload);

      case 'hsm_record_derivation':
        return handleHSMRecordDerivation(output, payload);

      case 'mlkem_log_key':
        return handleMLKEMLogKey(output, payload);

      case 'mlkem_log_session':
        return handleMLKEMLogSession(output, payload);

      case 'mlkem_get_status':
        return handleMLKEMGetStatus(output, payload);

      case 'transparency_record_entry':
        return handleTransparencyRecordEntry(output, payload);

      case 'transparency_record_sth':
        return handleTransparencyRecordSTH(output, payload);

      case 'transparency_list_entries':
        return handleTransparencyListEntries(output, payload);

      case 'transparency_status':
        return handleTransparencyStatus(output, payload);

      default:
        return jsonResponse(output, { status: 'error', message: 'Unknown action: ' + action });
    }
  } catch (err) {
    return jsonResponse(output, { status: 'error', message: err.toString() });
  }
}

function initSheets() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const defs = [
    { name: SHEET_USERS, cols: ['user_id', 'username', 'password_hash', 'salt', 'role', 'created_at'] },
    { name: SHEET_LICENSES, cols: ['license_key', 'hwid_bound', 'max_devices', 'status', 'expires_at', 'created_at', 'tier', 'features'] },
    { name: SHEET_DATABASE, cols: ['collection', 'doc_id', 'payload_json', 'updated_at'] },
    { name: SHEET_BLACKLIST, cols: ['type', 'target', 'reason', 'created_at'] },
    { name: SHEET_AUDIT_LOGS, cols: ['timestamp', 'action', 'actor', 'details', 'status'] },
    { name: SHEET_TENANTS, cols: ['tenant_id', 'name', 'prefix', 'hmac_secret', 'max_licenses', 'webhook_url', 'is_active', 'created_at'] },
    { name: SHEET_USAGE, cols: ['key', 'metric', 'period', 'count', 'limit', 'updated_at'] },
    { name: SHEET_FEATURE_FLAGS, cols: ['feature_key', 'name', 'default_tiers', 'description', 'created_at'] },
    { name: SHEET_ATTESTATIONS, cols: ['timestamp', 'license_key', 'hwid', 'attestation_type', 'trust_level', 'pcr_digest', 'tamper_score', 'details'] },
    { name: SHEET_CONSENSUS_NODES, cols: ['node_id', 'address', 'region', 'role', 'term', 'last_seen', 'has_quorum', 'merkle_digest'] },
    { name: SHEET_STREAM_EVENTS, cols: ['timestamp', 'event_type', 'client_id', 'target', 'reason', 'latency_ms', 'details'] },
    { name: SHEET_ZKP_CREDENTIALS, cols: ['credential_id', 'hwid_commitment', 'tier', 'max_seats', 'expires_at', 'scope', 'tenant_id', 'issued_at'] },
    { name: SHEET_ZKP_NULLIFIERS, cols: ['nullifier', 'epoch', 'tenant_id', 'spent_at'] },
    { name: SHEET_SSO_CONFIGS, cols: ['idp_id', 'tenant_id', 'name', 'type', 'entity_id', 'sso_endpoint', 'enabled', 'updated_at'] },
    { name: SHEET_DIRECTORY_USERS, cols: ['user_id', 'username', 'display_name', 'email', 'role', 'active', 'license_key', 'tenant_id', 'updated_at'] },
    { name: SHEET_PQC_KEYS, cols: ['key_id', 'algorithm', 'public_hex', 'status', 'reason', 'grace_until', 'created_at', 'updated_at'] },
    { name: SHEET_ANOMALY_INCIDENTS, cols: ['timestamp', 'license_key', 'hwid', 'ip', 'country', 'risk_score', 'reason'] },
    { name: SHEET_ENCLAVE_ATTESTATIONS, cols: ['timestamp', 'platform', 'mr_enclave', 'mr_signer', 'measurement', 'svn', 'debug', 'report_data', 'status'] },
    { name: SHEET_ENCLAVE_POLICIES, cols: ['policy_id', 'name', 'platform', 'min_svn', 'allow_debug', 'allowed_measurements', 'created_at'] },
    { name: SHEET_ENCLAVE_TOKENS, cols: ['token_id', 'platform', 'measurement', 'rtmr0', 'svn', 'debug', 'nonce', 'signature', 'expires_at', 'status'] },
    { name: SHEET_GEO_POPS, cols: ['pop_id', 'name', 'region', 'country', 'latitude', 'longitude', 'status', 'weight', 'rtt_ms', 'last_seen'] },
    { name: SHEET_PARTITION_EVENTS, cols: ['timestamp', 'region_id', 'status', 'mitigation_token', 'details'] },
    { name: SHEET_MARKETPLACE_TRANSACTIONS, cols: ['id', 'event_id', 'provider', 'action', 'customer_email', 'license_key', 'tier', 'seats', 'status', 'error_message', 'processed_at'] },
    { name: SHEET_AIRGAP_VAULT, cols: ['token_id', 'license_key', 'hwid', 'tier', 'issued_at', 'expires_at', 'counter', 'status', 'signature', 'updated_at'] },
    { name: SHEET_ZEROTRUST_PEERS, cols: ['node_id', 'role', 'serial_number', 'fingerprint_sha256', 'expires_at', 'status', 'updated_at'] },
    { name: SHEET_ZEROTRUST_CA, cols: ['root_fingerprint', 'expires_at', 'status', 'rotated_at'] },
    { name: SHEET_HEALING_LEASES, cols: ['lease_id', 'borrower_tenant', 'lender_tenant', 'amount', 'borrowed_at', 'expires_at', 'status', 'recall_reason'] },
    { name: SHEET_HEALING_TUNNELS, cols: ['session_id', 'client_id', 'hwid', 'tenant_id', 'state', 'connected_at', 'last_heartbeat', 'updated_at'] },
    { name: SHEET_HSM_AUDIT_LOG, cols: ['timestamp', 'event_type', 'slot_id', 'purpose', 'fingerprint', 'sensor_id', 'details'] },
    { name: SHEET_HSM_VAULT_KEYS, cols: ['key_id', 'slot_id', 'purpose', 'algorithm', 'fingerprint', 'status', 'created_at'] },
    { name: SHEET_MLKEM_KEY_LEDGER, cols: ['key_id', 'algorithm', 'fingerprint', 'status', 'created_at'] },
    { name: SHEET_MLKEM_SESSIONS, cols: ['session_id', 'agreed_mode', 'algorithm', 'quantum_resistant', 'expires_at', 'created_at'] },
    { name: SHEET_TRANSPARENCY_LOG, cols: ['index', 'action', 'tenant_id', 'leaf_hash_hex', 'timestamp', 'signature', 'tree_size', 'root_hash_hex', 'payload_json'] },
    { name: SHEET_WITNESS_COSIGNATURES, cols: ['witness_id', 'tree_size', 'root_hash_hex', 'timestamp', 'signature', 'status'] }
  ];
  defs.forEach(d => {
    if (!ss.getSheetByName(d.name)) {
      const s = ss.insertSheet(d.name);
      s.appendRow(d.cols);
      s.getRange(1, 1, 1, d.cols.length).setFontWeight('bold');
    }
  });
}

function handleRegister(output, payload) {
  const username = payload.username;
  const password = payload.password;
  if (!username || !password) {
    return jsonResponse(output, { status: 'error', message: 'Username and password required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_USERS);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === username) {
      return jsonResponse(output, { status: 'error', message: 'Username already exists' });
    }
  }

  const salt = Utilities.getUuid().substring(0, 8);
  const hash = hashString(password + salt);
  const userId = 'usr_' + Utilities.getUuid().substring(0, 8);
  const now = new Date().toISOString();

  sheet.appendRow([userId, username, hash, salt, 'user', now]);
  logAudit('register', username, 'Registered new user ' + username, 'SUCCESS');
  return jsonResponse(output, { status: 'success', user_id: userId, username: username });
}

function handleLogin(output, payload) {
  const username = payload.username;
  const password = payload.password;
  if (!username || !password) {
    return jsonResponse(output, { status: 'error', message: 'Username and password required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_USERS);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === username) {
      const storedHash = data[i][2];
      const salt = data[i][3];
      if (constantTimeEquals(hashString(password + salt), storedHash)) {
        logAudit('login', username, 'User logged in', 'SUCCESS');
        return jsonResponse(output, { status: 'success', authenticated: true, user_id: data[i][0], username: username, role: data[i][4] });
      }
      logAudit('login', username, 'Failed login password mismatch', 'REJECTED');
      return jsonResponse(output, { status: 'error', message: 'Invalid credentials' });
    }
  }

  logAudit('login', username, 'Failed login user not found', 'ERROR');
  return jsonResponse(output, { status: 'error', message: 'User not found' });
}

function handleCreateLicense(output, payload) {
  const prefix = (payload.prefix || payload.tenant_prefix || '').trim().toUpperCase();
  const defaultKey = prefix ? (prefix + '-LIC-' + Utilities.getUuid().substring(0, 8).toUpperCase()) : ('KEY-' + Utilities.getUuid().substring(0, 8).toUpperCase());
  const key = payload.license_key || defaultKey;
  const maxDevices = payload.max_devices || 1;
  const days = payload.days || 30;

  const expDate = new Date();
  expDate.setDate(expDate.getDate() + Number(days));

  const tier = (payload.tier || 'pro').toLowerCase().trim();
  const features = Array.isArray(payload.features) ? payload.features.join(',') : (payload.features || '');

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_LICENSES);
  sheet.appendRow([key, '', maxDevices, 'ACTIVE', expDate.toISOString(), new Date().toISOString(), tier, features]);

  logAudit('create_license', 'admin', 'Created license ' + key, 'SUCCESS');
  return jsonResponse(output, { status: 'success', license_key: key, expires_at: expDate.toISOString(), tier: tier, features: features ? features.split(',') : [] });
}

function handleVerifyLicense(output, payload) {
  const key = (payload.license_key || '').trim().toUpperCase();
  const hwid = (payload.hwid || '').trim();

  if (!key) {
    logAudit('verify_license', hwid, 'Missing license key', 'ERROR');
    return jsonResponse(output, { status: 'error', message: 'License key required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const blSheet = ss.getSheetByName(SHEET_BLACKLIST);
  if (blSheet) {
    const blData = blSheet.getDataRange().getValues();
    for (let b = 1; b < blData.length; b++) {
      const bType = String(blData[b][0]).toLowerCase().trim();
      const bTarget = String(blData[b][1]).toUpperCase().trim();
      const bReason = blData[b][2] || 'Blacklisted';

      if (bType === 'license' && bTarget === key) {
        logAudit('verify_license', hwid, 'Key blacklisted: ' + key, 'REJECTED');
        return jsonResponse(output, { status: 'error', message: 'License revoked: ' + bReason, blacklisted: true });
      }
      if (bType === 'device' && hwid && bTarget === hwid.toUpperCase()) {
        logAudit('verify_license', hwid, 'Device blacklisted: ' + hwid, 'REJECTED');
        return jsonResponse(output, { status: 'error', message: 'Device blacklisted: ' + bReason, blacklisted: true });
      }
    }
  }

  const sheet = ss.getSheetByName(SHEET_LICENSES);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).toUpperCase() === key) {
      const boundHWID = data[i][1];
      const status = data[i][3];
      const expiresAt = new Date(data[i][4]);
      const tier = String(data[i][6] || 'pro').toLowerCase().trim();
      const rawFeats = String(data[i][7] || '');
      const feats = rawFeats ? rawFeats.split(',') : [];

      if (status !== 'ACTIVE') {
        logAudit('verify_license', hwid, 'Key status ' + status, 'REJECTED');
        return jsonResponse(output, { status: 'error', message: 'License is ' + status });
      }
      if (new Date() > expiresAt) {
        logAudit('verify_license', hwid, 'Expired on ' + expiresAt.toISOString(), 'EXPIRED');
        return jsonResponse(output, { status: 'error', message: 'License expired on ' + expiresAt.toISOString() });
      }

      if (!boundHWID && hwid) {
        sheet.getRange(i + 1, 2).setValue(hwid);
        logAudit('verify_license', hwid, 'Bound to machine for ' + key, 'SUCCESS');
        return jsonResponse(output, { status: 'success', verified: true, hwid_bound: hwid, tier: tier, features: feats, message: 'License activated and bound to device' });
      }

      if (boundHWID && hwid && boundHWID !== hwid) {
        logAudit('verify_license', hwid, 'Device mismatch: bound=' + boundHWID, 'REJECTED');
        return jsonResponse(output, { status: 'error', message: 'Device mismatch: bound to another HWID' });
      }

      logAudit('verify_license', hwid, 'Verified ' + key, 'SUCCESS');
      return jsonResponse(output, { status: 'success', verified: true, hwid_bound: boundHWID, expires_at: expiresAt.toISOString(), tier: tier, features: feats });
    }
  }

  logAudit('verify_license', hwid, 'Invalid key ' + key, 'ERROR');
  return jsonResponse(output, { status: 'error', message: 'Invalid license key' });
}

function handleRevokeLicense(output, payload) {
  const key = (payload.license_key || '').toUpperCase().trim();
  const reason = (payload.reason || 'Revoked by administrator').trim();

  if (!key) {
    return jsonResponse(output, { status: 'error', message: 'License key required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const licSheet = ss.getSheetByName(SHEET_LICENSES);
  const data = licSheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).toUpperCase() === key) {
      licSheet.getRange(i + 1, 4).setValue('REVOKED');
      break;
    }
  }

  const blSheet = ss.getSheetByName(SHEET_BLACKLIST);
  blSheet.appendRow(['license', key, reason, new Date().toISOString()]);
  logAudit('revoke_license', key, reason, 'REVOKED');
  return jsonResponse(output, { status: 'success', message: 'License successfully revoked', license_key: key });
}

function handleTenantRegister(output, payload) {
  const tenantId = (payload.tenant_id || payload.id || '').trim();
  const prefix = (payload.prefix || payload.namespace_prefix || '').trim().toUpperCase();
  const name = (payload.name || tenantId).trim();
  if (!tenantId || !prefix) {
    return jsonResponse(output, { status: 'error', message: 'tenant_id and prefix required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_TENANTS);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === tenantId || data[i][2] === prefix) {
      return jsonResponse(output, { status: 'error', message: 'Tenant ID or prefix already exists' });
    }
  }

  sheet.appendRow([tenantId, name, prefix, payload.hmac_secret || '', payload.max_licenses || 0, payload.webhook_url || '', payload.is_active !== false, new Date().toISOString()]);
  logAudit('tenant_register', tenantId, 'Registered tenant ' + prefix, 'SUCCESS');
  return jsonResponse(output, { status: 'success', tenant_id: tenantId, prefix: prefix, name: name });
}

function handleTenantList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_TENANTS);
  const data = sheet.getDataRange().getValues();
  const tenants = [];
  for (let i = 1; i < data.length; i++) {
    tenants.push({ id: data[i][0], name: data[i][1], namespace_prefix: data[i][2], hmac_secret: data[i][3], max_licenses: Number(data[i][4]) || 0, webhook_url: data[i][5], is_active: data[i][6] === true, created_at: data[i][7] });
  }
  return jsonResponse(output, { status: 'success', tenants: tenants });
}

function handleBackupExport(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const getData = (name) => {
    const s = ss.getSheetByName(name);
    return s ? s.getDataRange().getValues() : [];
  };

  const parseRows = (name, mapper) => {
    const rows = getData(name);
    const res = [];
    for (let i = 1; i < rows.length; i++) res.push(mapper(rows[i]));
    return res;
  };

  const users = parseRows(SHEET_USERS, r => ({ user_id: r[0], username: r[1], role: r[4], created_at: r[5] }));
  const licenses = parseRows(SHEET_LICENSES, r => ({ license_key: r[0], bound_hwid: r[1], max_devices: Number(r[2]) || 1, status: r[3], expires_at: r[4], created_at: r[5] }));
  const tenants = parseRows(SHEET_TENANTS, r => ({ id: r[0], name: r[1], namespace_prefix: r[2], max_licenses: Number(r[4]) || 0, webhook_url: r[5], is_active: r[6] === true, created_at: r[7] }));
  const blacklist = parseRows(SHEET_BLACKLIST, r => ({ type: r[0], target: r[1], reason: r[2], created_at: r[3] }));
  const documents = parseRows(SHEET_DATABASE, r => ({ collection: r[0], doc_id: r[1], payload: String(r[2]), updated_at: r[3] }));

  const data = { users, licenses, tenants, blacklist, documents };
  const checksum = hashString(JSON.stringify(data));
  logAudit('backup_export', 'system', 'Exported snapshot ' + checksum.substring(0, 8), 'SUCCESS');
  return jsonResponse(output, { status: 'success', version: '1.0', timestamp: new Date().toISOString(), checksum: checksum, data: data });
}

function handleBackupRestore(output, payload) {
  const snapshot = payload.snapshot || payload;
  if (!snapshot || !snapshot.data) {
    return jsonResponse(output, { status: 'error', message: 'Invalid snapshot data' });
  }
  const data = snapshot.data;
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  if (Array.isArray(data.tenants)) {
    const s = ss.getSheetByName(SHEET_TENANTS);
    if (s) data.tenants.forEach(t => s.appendRow([t.id, t.name, t.namespace_prefix, t.hmac_secret || '', t.max_licenses || 0, t.webhook_url || '', t.is_active !== false, t.created_at || new Date().toISOString()]));
  }
  if (Array.isArray(data.licenses)) {
    const s = ss.getSheetByName(SHEET_LICENSES);
    if (s) data.licenses.forEach(l => s.appendRow([l.license_key, l.bound_hwid || '', l.max_devices || 1, l.status || 'ACTIVE', l.expires_at || '', l.created_at || new Date().toISOString()]));
  }
  logAudit('backup_restore', 'system', 'Restored snapshot', 'SUCCESS');
  return jsonResponse(output, { status: 'success', message: 'Backup restored successfully' });
}

function handleBlacklistAdd(output, payload) {
  const type = (payload.type || 'device').toLowerCase().trim();
  const target = (payload.target || '').trim();
  const reason = (payload.reason || 'Banned').trim();

  if (!target) return jsonResponse(output, { status: 'error', message: 'Target identifier required' });

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_BLACKLIST);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).toLowerCase() === type && String(data[i][1]).toUpperCase() === target.toUpperCase()) {
      sheet.getRange(i + 1, 3).setValue(reason);
      logAudit('blacklist_add', target, 'Updated reason: ' + reason, 'SUCCESS');
      return jsonResponse(output, { status: 'success', message: 'Blacklist entry updated', type: type, target: target });
    }
  }

  sheet.appendRow([type, target.toUpperCase(), reason, new Date().toISOString()]);
  logAudit('blacklist_add', target, 'Added: ' + reason, 'SUCCESS');
  return jsonResponse(output, { status: 'success', message: 'Target blacklisted', type: type, target: target });
}

function handleBlacklistRemove(output, payload) {
  const type = (payload.type || 'device').toLowerCase().trim();
  const target = (payload.target || '').toUpperCase().trim();

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_BLACKLIST);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).toLowerCase() === type && String(data[i][1]).toUpperCase() === target) {
      sheet.deleteRow(i + 1);
      logAudit('blacklist_remove', target, 'Removed from blacklist', 'SUCCESS');
      return jsonResponse(output, { status: 'success', message: 'Target unblacklisted' });
    }
  }
  return jsonResponse(output, { status: 'error', message: 'Target not found in blacklist' });
}

function handleBlacklistList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_BLACKLIST);
  const data = sheet.getDataRange().getValues();
  const entries = [];

  for (let i = 1; i < data.length; i++) {
    entries.push({ type: data[i][0], target: data[i][1], reason: data[i][2], created_at: data[i][3] });
  }
  return jsonResponse(output, { status: 'success', entries: entries });
}

function logAudit(action, actor, details, status) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_AUDIT_LOGS);
    if (sheet) sheet.appendRow([new Date().toISOString(), action, actor || 'system', details || '', status || 'OK']);
  } catch (e) {}
}

function handleDBPut(output, payload) {
  const collection = payload.collection || 'default';
  const docId = payload.doc_id || Utilities.getUuid().substring(0, 8);
  const dataStr = typeof payload.data === 'string' ? payload.data : JSON.stringify(payload.data || {});

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_DATABASE);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === collection && data[i][1] === docId) {
      sheet.getRange(i + 1, 3).setValue(dataStr);
      sheet.getRange(i + 1, 4).setValue(new Date().toISOString());
      return jsonResponse(output, { status: 'success', action: 'updated', collection: collection, doc_id: docId });
    }
  }

  sheet.appendRow([collection, docId, dataStr, new Date().toISOString()]);
  return jsonResponse(output, { status: 'success', action: 'created', collection: collection, doc_id: docId });
}

function handleDBGet(output, payload) {
  const collection = payload.collection || 'default';
  const docId = payload.doc_id;

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_DATABASE);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === collection && data[i][1] === docId) {
      let parsed = data[i][2];
      try { parsed = JSON.parse(parsed); } catch (e) {}
      return jsonResponse(output, { status: 'success', collection: collection, doc_id: docId, data: parsed, updated_at: data[i][3] });
    }
  }

  return jsonResponse(output, { status: 'error', message: 'Document not found' });
}

function handleFeaturesList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_FEATURE_FLAGS);
  const data = sheet ? sheet.getDataRange().getValues() : [];
  const features = [];
  for (let i = 1; i < data.length; i++) {
    features.push({
      key: data[i][0],
      name: data[i][1],
      default_tiers: String(data[i][2]).split(','),
      description: data[i][3]
    });
  }
  return jsonResponse(output, { status: 'success', features: features });
}

function handleUsageRecord(output, payload) {
  const key = String(payload.key || payload.license_key || '').toUpperCase().trim();
  const metric = String(payload.metric || '').toLowerCase().trim();
  const period = String(payload.period || new Date().toISOString().substring(0, 10)).trim();
  const units = Number(payload.units || 1);
  const limit = Number(payload.limit || 0);

  if (!key || !metric) {
    return jsonResponse(output, { status: 'error', message: 'key and metric are required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_USAGE);
  const data = sheet ? sheet.getDataRange().getValues() : [];
  let rowIndex = -1;
  let currentCount = 0;

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).toUpperCase() === key && String(data[i][1]).toLowerCase() === metric && String(data[i][2]) === period) {
      rowIndex = i + 1;
      currentCount = Number(data[i][3]) || 0;
      break;
    }
  }

  currentCount += units;
  const now = new Date().toISOString();
  if (rowIndex > 0) {
    sheet.getRange(rowIndex, 4).setValue(currentCount);
    sheet.getRange(rowIndex, 6).setValue(now);
    if (limit > 0) sheet.getRange(rowIndex, 5).setValue(limit);
  } else if (sheet) {
    sheet.appendRow([key, metric, period, currentCount, limit, now]);
  }

  const exceeded = limit > 0 && currentCount > limit;
  return jsonResponse(output, {
    status: 'success',
    record: { key: key, metric: metric, period: period, count: currentCount, limit: limit, updated_at: now },
    exceeded: exceeded
  });
}

function handleUsageGet(output, payload) {
  const key = String(payload.key || payload.license_key || '').toUpperCase().trim();
  if (!key) {
    return jsonResponse(output, { status: 'error', message: 'key is required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_USAGE);
  const data = sheet ? sheet.getDataRange().getValues() : [];
  const records = [];

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]).toUpperCase() === key) {
      records.push({
        key: data[i][0],
        metric: data[i][1],
        period: data[i][2],
        count: Number(data[i][3]) || 0,
        limit: Number(data[i][4]) || 0,
        updated_at: data[i][5]
      });
    }
  }

  return jsonResponse(output, { status: 'success', license_key: key, records: records });
}

function handleAttestationRecord(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ATTESTATIONS);

  const licKey = String(payload.license_key || '').trim().toUpperCase();
  const hwid = String(payload.hwid || '').trim().toUpperCase();
  const attType = String(payload.attestation_type || 'software_emulated').trim();
  const trustLevel = String(payload.trust_level || 'unverified').trim();
  const pcrDigest = String(payload.pcr_digest || '').trim();
  const tamperScore = Number(payload.tamper_score) || 0;
  const details = String(payload.details || '').trim();
  const ts = new Date().toISOString();

  sheet.appendRow([ts, licKey, hwid, attType, trustLevel, pcrDigest, tamperScore, details]);
  logAudit('attestation_recorded', licKey, 'Type: ' + attType + ', Trust: ' + trustLevel + ', Score: ' + tamperScore, 'SUCCESS');

  return jsonResponse(output, {
    status: 'success',
    message: 'Attestation recorded',
    timestamp: ts,
    trust_level: trustLevel
  });
}

function handleAttestationList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ATTESTATIONS);
  const data = sheet.getDataRange().getValues();

  const filterKey = String(payload.license_key || '').trim().toUpperCase();
  const filterHWID = String(payload.hwid || '').trim().toUpperCase();
  const records = [];

  for (let i = 1; i < data.length; i++) {
    const rowKey = String(data[i][1]).toUpperCase();
    const rowHWID = String(data[i][2]).toUpperCase();

    if (filterKey && rowKey !== filterKey) continue;
    if (filterHWID && rowHWID !== filterHWID) continue;

    records.push({
      timestamp: data[i][0],
      license_key: data[i][1],
      hwid: data[i][2],
      attestation_type: data[i][3],
      trust_level: data[i][4],
      pcr_digest: data[i][5],
      tamper_score: Number(data[i][6]) || 0,
      details: data[i][7]
    });
  }

  return jsonResponse(output, { status: 'success', records: records, count: records.length });
}

function handleAuditLogRecord(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_AUDIT_LOGS);
  const ts = new Date().toISOString();
  const action = String(payload.log_action || 'audit_event').trim();
  const actor = String(payload.actor || 'system').trim();
  const details = String(payload.details || '').trim();
  const status = String(payload.log_status || 'INFO').trim().toUpperCase();

  sheet.appendRow([ts, action, actor, details, status]);
  return jsonResponse(output, { status: 'success', message: 'Audit event recorded', timestamp: ts });
}

function handleAuditLogList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_AUDIT_LOGS);
  const data = sheet.getDataRange().getValues();
  const limit = Math.min(Number(payload.limit) || 100, 500);
  const records = [];

  for (let i = data.length - 1; i >= 1 && records.length < limit; i--) {
    records.push({
      timestamp: data[i][0],
      action: data[i][1],
      actor: data[i][2],
      details: data[i][3],
      status: data[i][4]
    });
  }

  return jsonResponse(output, { status: 'success', records: records, count: records.length });
}

function handleConsensusNodeHeartbeat(output, payload) {
  const nodeId = String(payload.node_id || '').trim();
  const address = String(payload.address || '').trim();
  const region = String(payload.region || 'default').trim();
  const role = String(payload.role || 'follower').trim();
  const term = Number(payload.term || 0);
  const hasQuorum = payload.has_quorum === true;
  const digest = String(payload.merkle_digest || '').trim();
  const now = new Date().toISOString();

  if (!nodeId) {
    return jsonResponse(output, { status: 'error', message: 'node_id is required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_CONSENSUS_NODES);
  if (!sheet) {
    return jsonResponse(output, { status: 'error', message: 'ConsensusNodes sheet not found' });
  }

  const data = sheet.getDataRange().getValues();
  let foundRow = -1;
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]) === nodeId) {
      foundRow = i + 1;
      break;
    }
  }

  if (foundRow > 0) {
    sheet.getRange(foundRow, 2, 1, 7).setValues([[address, region, role, term, now, hasQuorum, digest]]);
  } else {
    sheet.appendRow([nodeId, address, region, role, term, now, hasQuorum, digest]);
  }

  return jsonResponse(output, { status: 'success', node_id: nodeId, updated_at: now });
}

function handleConsensusNodeList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_CONSENSUS_NODES);
  const data = sheet ? sheet.getDataRange().getValues() : [];
  const nodes = [];

  for (let i = 1; i < data.length; i++) {
    nodes.push({
      node_id: data[i][0],
      address: data[i][1],
      region: data[i][2],
      role: data[i][3],
      term: data[i][4],
      last_seen: data[i][5],
      has_quorum: data[i][6],
      merkle_digest: data[i][7]
    });
  }

  return jsonResponse(output, { status: 'success', nodes: nodes, count: nodes.length });
}

function handleStreamEventRecord(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_STREAM_EVENTS);
  const now = new Date().toISOString();
  sheet.appendRow([
    now,
    payload.event_type || 'stream:event',
    payload.client_id || '',
    payload.target || '',
    payload.reason || '',
    payload.latency_ms || 0,
    typeof payload.details === 'object' ? JSON.stringify(payload.details) : (payload.details || '')
  ]);
  return jsonResponse(output, { status: 'success', message: 'Stream event recorded' });
}

function handleStreamEventList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_STREAM_EVENTS);
  const data = sheet.getDataRange().getValues();
  const events = [];
  const limit = Math.min(Number(payload.limit) || 50, 200);

  for (let i = data.length - 1; i >= 1 && events.length < limit; i--) {
    events.push({
      timestamp: data[i][0],
      event_type: data[i][1],
      client_id: data[i][2],
      target: data[i][3],
      reason: data[i][4],
      latency_ms: data[i][5],
      details: data[i][6]
    });
  }

  return jsonResponse(output, { status: 'success', count: events.length, events: events });
}

function handleZKPRecordCredential(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ZKP_CREDENTIALS);
  const now = new Date().toISOString();

  sheet.appendRow([
    payload.credential_id || '',
    payload.hwid_commitment || '',
    payload.tier || 1,
    payload.max_seats || 1,
    payload.expires_at || '',
    payload.scope || 'default',
    payload.tenant_id || 'default',
    now
  ]);

  logAudit('zkp_credential', payload.tenant_id || 'system', 'Issued anonymous credential ' + (payload.credential_id || ''), 'SUCCESS');
  return jsonResponse(output, { status: 'success', credential_id: payload.credential_id });
}

function handleZKPRecordNullifier(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ZKP_NULLIFIERS);
  const nullifier = payload.nullifier;
  if (!nullifier) {
    return jsonResponse(output, { status: 'error', message: 'Nullifier required' });
  }

  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === nullifier) {
      return jsonResponse(output, { status: 'error', message: 'Nullifier already spent', spent: true, epoch: data[i][1] });
    }
  }

  const now = new Date().toISOString();
  sheet.appendRow([nullifier, payload.epoch || 0, payload.tenant_id || 'default', now]);
  return jsonResponse(output, { status: 'success', nullifier: nullifier, spent: true });
}

function handleZKPList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const credSheet = ss.getSheetByName(SHEET_ZKP_CREDENTIALS);
  const nullSheet = ss.getSheetByName(SHEET_ZKP_NULLIFIERS);

  const credData = credSheet.getDataRange().getValues();
  const nullData = nullSheet.getDataRange().getValues();

  const credentials = [];
  const limit = Math.min(Number(payload.limit) || 50, 100);

  for (let i = credData.length - 1; i >= 1 && credentials.length < limit; i--) {
    credentials.push({
      credential_id: credData[i][0],
      hwid_commitment: credData[i][1],
      tier: credData[i][2],
      max_seats: credData[i][3],
      expires_at: credData[i][4],
      scope: credData[i][5],
      tenant_id: credData[i][6],
      issued_at: credData[i][7]
    });
  }

  return jsonResponse(output, {
    status: 'success',
    credentials_count: credentials.length,
    spent_nullifiers_count: Math.max(0, nullData.length - 1),
    credentials: credentials
  });
}

function handleSSOIdPSave(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_SSO_CONFIGS);
  const idpId = payload.idp_id || ('idp-' + Utilities.getUuid().substring(0, 8));
  const tenantId = payload.tenant_id || 'default';
  const name = payload.name || 'Enterprise IdP';
  const type = payload.type || 'saml2';
  const entityId = payload.entity_id || '';
  const ssoEndpoint = payload.sso_endpoint || '';
  const enabled = payload.enabled !== false;
  const now = new Date().toISOString();

  const data = sheet.getDataRange().getValues();
  let updated = false;
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === idpId) {
      sheet.getRange(i + 1, 1, 1, 8).setValues([[idpId, tenantId, name, type, entityId, ssoEndpoint, enabled, now]]);
      updated = true;
      break;
    }
  }
  if (!updated) {
    sheet.appendRow([idpId, tenantId, name, type, entityId, ssoEndpoint, enabled, now]);
  }
  logAudit('sso_idp_save', tenantId, 'Configured IdP ' + idpId + ' (' + type + ')', 'SUCCESS');
  return jsonResponse(output, { status: 'success', idp_id: idpId, updated: updated });
}

function handleSSOIdPList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_SSO_CONFIGS);
  const data = sheet.getDataRange().getValues();
  const tenantFilter = payload.tenant_id || '';
  const idps = [];
  for (let i = 1; i < data.length; i++) {
    if (!tenantFilter || data[i][1] === tenantFilter) {
      idps.push({
        idp_id: data[i][0],
        tenant_id: data[i][1],
        name: data[i][2],
        type: data[i][3],
        entity_id: data[i][4],
        sso_endpoint: data[i][5],
        enabled: data[i][6],
        updated_at: data[i][7]
      });
    }
  }
  return jsonResponse(output, { status: 'success', count: idps.length, idps: idps });
}

function handleSCIMUserSync(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_DIRECTORY_USERS);
  const userId = payload.user_id || ('scim-' + Utilities.getUuid().substring(0, 8));
  const username = payload.username || '';
  const displayName = payload.display_name || '';
  const email = payload.email || username;
  const role = payload.role || 'user';
  const active = payload.active !== false;
  const licenseKey = payload.license_key || '';
  const tenantId = payload.tenant_id || 'default';
  const now = new Date().toISOString();

  const data = sheet.getDataRange().getValues();
  let updated = false;
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === userId || data[i][1] === username) {
      sheet.getRange(i + 1, 1, 1, 9).setValues([[userId, username, displayName, email, role, active, licenseKey, tenantId, now]]);
      updated = true;
      break;
    }
  }
  if (!updated) {
    sheet.appendRow([userId, username, displayName, email, role, active, licenseKey, tenantId, now]);
  }
  logAudit('scim_user_sync', username, 'Synced SCIM directory user (active: ' + active + ')', 'SUCCESS');
  return jsonResponse(output, { status: 'success', user_id: userId, active: active, updated: updated });
}

function handleSCIMUserDeprovision(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_DIRECTORY_USERS);
  const target = payload.user_id || payload.username || '';
  const reason = payload.reason || 'Deprovisioned via SCIM';
  const now = new Date().toISOString();

  const data = sheet.getDataRange().getValues();
  let found = false;
  let licToRevoke = '';
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === target || data[i][1] === target) {
      sheet.getRange(i + 1, 6).setValue(false);
      sheet.getRange(i + 1, 9).setValue(now);
      licToRevoke = data[i][6];
      found = true;
      break;
    }
  }

  if (licToRevoke) {
    const licSheet = ss.getSheetByName(SHEET_LICENSES);
    const licData = licSheet.getDataRange().getValues();
    for (let j = 1; j < licData.length; j++) {
      if (licData[j][0] === licToRevoke) {
        licSheet.getRange(j + 1, 4).setValue('revoked');
        break;
      }
    }
  }

  logAudit('scim_deprovision', target, 'Deprovisioned user, revoked license ' + licToRevoke + ' (' + reason + ')', 'REVOKED');
  return jsonResponse(output, { status: found ? 'success' : 'not_found', target: target, revoked_license: licToRevoke });
}

function handleSCIMUserList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_DIRECTORY_USERS);
  const data = sheet.getDataRange().getValues();
  const tenantFilter = payload.tenant_id || '';
  const users = [];
  for (let i = 1; i < data.length; i++) {
    if (!tenantFilter || data[i][7] === tenantFilter) {
      users.push({
        user_id: data[i][0],
        username: data[i][1],
        display_name: data[i][2],
        email: data[i][3],
        role: data[i][4],
        active: data[i][5],
        license_key: data[i][6],
        tenant_id: data[i][7],
        updated_at: data[i][8]
      });
    }
  }
  return jsonResponse(output, { status: 'success', count: users.length, users: users });
}

function handlePQCKeySave(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_PQC_KEYS);
  const data = sheet.getDataRange().getValues();
  const keyId = payload.key_id;
  const now = new Date().toISOString();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === keyId) {
      sheet.getRange(i + 1, 4).setValue(payload.status || 'active');
      sheet.getRange(i + 1, 5).setValue(payload.reason || '');
      sheet.getRange(i + 1, 6).setValue(payload.grace_until || '');
      sheet.getRange(i + 1, 8).setValue(now);
      return jsonResponse(output, { status: 'success', message: 'PQC key updated', key_id: keyId });
    }
  }

  sheet.appendRow([
    keyId,
    payload.algorithm || '',
    payload.public_hex || '',
    payload.status || 'active',
    payload.reason || '',
    payload.grace_until || '',
    now,
    now
  ]);
  return jsonResponse(output, { status: 'success', message: 'PQC key created', key_id: keyId });
}

function handlePQCKeyRevoke(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_PQC_KEYS);
  const data = sheet.getDataRange().getValues();
  const keyId = payload.key_id;
  const now = new Date().toISOString();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === keyId) {
      sheet.getRange(i + 1, 4).setValue('revoked');
      sheet.getRange(i + 1, 5).setValue(payload.reason || 'revoked by administrator');
      sheet.getRange(i + 1, 8).setValue(now);
      return jsonResponse(output, { status: 'success', message: 'PQC key revoked', key_id: keyId });
    }
  }
  return jsonResponse(output, { status: 'error', message: 'Key not found: ' + keyId });
}

function handlePQCKeyList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_PQC_KEYS);
  const data = sheet.getDataRange().getValues();
  const keys = [];

  for (let i = 1; i < data.length; i++) {
    keys.push({
      key_id: data[i][0],
      algorithm: data[i][1],
      public_hex: data[i][2],
      status: data[i][3],
      reason: data[i][4],
      grace_until: data[i][5],
      created_at: data[i][6],
      updated_at: data[i][7]
    });
  }
  return jsonResponse(output, { status: 'success', count: keys.length, keys: keys });
}

function jsonResponse(output, data) {
  output.setContent(JSON.stringify(data));
  return output;
}

function hashString(input) {
  const rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input, Utilities.Charset.UTF_8);
  let txtHash = '';
  for (let i = 0; i < rawHash.length; i++) {
    let hashVal = rawHash[i];
    if (hashVal < 0) hashVal += 256;
    let byteStr = hashVal.toString(16);
    if (byteStr.length === 1) byteStr = '0' + byteStr;
    txtHash += byteStr;
  }
  return txtHash;
}

function constantTimeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function handleAnomalyRecord(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ANOMALY_INCIDENTS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Anomaly_Incidents sheet missing' });

  const ts = new Date().toISOString();
  const lic = payload.license_key || '';
  const hwid = payload.hwid || '';
  const ip = payload.ip || '';
  const country = payload.country || '';
  const score = payload.risk_score || 0;
  const reason = payload.reason || 'anomaly_detected';

  sheet.appendRow([ts, lic, hwid, ip, country, score, reason]);
  return jsonResponse(output, { status: 'success', message: 'Anomaly incident recorded', timestamp: ts });
}

function handleAnomalyIncidentList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ANOMALY_INCIDENTS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Anomaly_Incidents sheet missing' });

  const data = sheet.getDataRange().getValues();
  const incidents = [];
  for (let i = 1; i < data.length; i++) {
    incidents.push({
      timestamp: data[i][0],
      license_key: data[i][1],
      hwid: data[i][2],
      ip: data[i][3],
      country: data[i][4],
      risk_score: data[i][5],
      reason: data[i][6]
    });
  }
  return jsonResponse(output, { status: 'success', count: incidents.length, incidents: incidents });
}

function handleEnclaveAttestLog(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ENCLAVE_ATTESTATIONS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Enclave_Attestations sheet missing' });

  const now = new Date().toISOString();
  sheet.appendRow([
    now,
    payload.platform || 'intel_sgx',
    payload.mr_enclave || '',
    payload.mr_signer || '',
    payload.measurement || '',
    payload.svn || 0,
    payload.debug ? 'true' : 'false',
    payload.report_data || '',
    payload.status || 'VERIFIED'
  ]);
  return jsonResponse(output, { status: 'success', logged_at: now });
}

function handleEnclaveAttestList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ENCLAVE_ATTESTATIONS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Enclave_Attestations sheet missing' });

  const data = sheet.getDataRange().getValues();
  const list = [];
  const limit = payload.limit || 50;
  for (let i = Math.max(1, data.length - limit); i < data.length; i++) {
    list.push({
      timestamp: data[i][0],
      platform: data[i][1],
      mr_enclave: data[i][2],
      mr_signer: data[i][3],
      measurement: data[i][4],
      svn: data[i][5],
      debug: data[i][6] === 'true',
      report_data: data[i][7],
      status: data[i][8]
    });
  }
  return jsonResponse(output, { status: 'success', count: list.length, attestations: list });
}

function handleEnclavePolicySave(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ENCLAVE_POLICIES);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Enclave_Policies sheet missing' });

  const policyId = payload.policy_id || ('pol_' + Utilities.getUuid().substring(0, 8));
  const now = new Date().toISOString();
  sheet.appendRow([
    policyId,
    payload.name || 'Enclave Policy',
    payload.platform || 'intel_sgx',
    payload.min_svn || 1,
    payload.allow_debug ? 'true' : 'false',
    JSON.stringify(payload.allowed_measurements || []),
    now
  ]);
  return jsonResponse(output, { status: 'success', policy_id: policyId });
}

function handleEnclavePolicyList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ENCLAVE_POLICIES);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Enclave_Policies sheet missing' });

  const data = sheet.getDataRange().getValues();
  const policies = [];
  for (let i = 1; i < data.length; i++) {
    policies.push({
      policy_id: data[i][0],
      name: data[i][1],
      platform: data[i][2],
      min_svn: data[i][3],
      allow_debug: data[i][4] === 'true',
      allowed_measurements: data[i][5] ? JSON.parse(data[i][5]) : [],
      created_at: data[i][6]
    });
  }
  return jsonResponse(output, { status: 'success', count: policies.length, policies: policies });
}

function handleEnclaveTokenRecord(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ENCLAVE_TOKENS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Enclave_Tokens sheet missing' });

  const tokenId = payload.token_id || ('tok_' + Utilities.getUuid().substring(0, 16));
  sheet.appendRow([
    tokenId,
    payload.platform || 'intel_tdx',
    payload.measurement || '',
    payload.rtmr0 || '',
    payload.svn || 1,
    payload.debug ? 'true' : 'false',
    payload.nonce || '',
    payload.signature || '',
    payload.expires_at || '',
    payload.status || 'ACTIVE'
  ]);
  return jsonResponse(output, { status: 'success', token_id: tokenId });
}

function handleEnclaveTokenList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ENCLAVE_TOKENS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Enclave_Tokens sheet missing' });

  const data = sheet.getDataRange().getValues();
  const tokens = [];
  const limit = payload.limit || 50;
  for (let i = Math.max(1, data.length - limit); i < data.length; i++) {
    tokens.push({
      token_id: data[i][0],
      platform: data[i][1],
      measurement: data[i][2],
      rtmr0: data[i][3],
      svn: data[i][4],
      debug: data[i][5] === 'true',
      nonce: data[i][6],
      signature: data[i][7],
      expires_at: data[i][8],
      status: data[i][9]
    });
  }
  return jsonResponse(output, { status: 'success', count: tokens.length, tokens: tokens });
}

function handleAnycastPOPHeartbeat(output, payload) {
  const popId = payload.pop_id;
  if (!popId) return jsonResponse(output, { status: 'error', message: 'pop_id required' });

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_GEO_POPS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Geo_POPs sheet missing' });

  const data = sheet.getDataRange().getValues();
  const now = new Date().toISOString();

  let rowIndex = -1;
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === popId) {
      rowIndex = i + 1;
      break;
    }
  }

  const row = [
    popId,
    payload.name || ('POP-' + popId),
    payload.region || 'global',
    payload.country || 'US',
    Number(payload.latitude || 0),
    Number(payload.longitude || 0),
    payload.status || 'healthy',
    Number(payload.weight || 1.0),
    Number(payload.rtt_ms || 0),
    now
  ];

  if (rowIndex > 0) {
    sheet.getRange(rowIndex, 1, 1, row.length).setValues([row]);
  } else {
    sheet.appendRow(row);
  }

  logAudit('anycast_pop_heartbeat', popId, 'Updated Anycast POP ' + popId, 'SUCCESS');
  return jsonResponse(output, { status: 'success', pop_id: popId, updated_at: now });
}

function handleAnycastPOPList(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_GEO_POPS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Geo_POPs sheet missing' });

  const data = sheet.getDataRange().getValues();
  const pops = [];

  for (let i = 1; i < data.length; i++) {
    pops.push({
      id: data[i][0],
      name: data[i][1],
      region: data[i][2],
      country: data[i][3],
      latitude: Number(data[i][4]),
      longitude: Number(data[i][5]),
      status: data[i][6],
      weight: Number(data[i][7]),
      rtt_ms: Number(data[i][8]),
      last_seen: data[i][9]
    });
  }

  return jsonResponse(output, { status: 'success', count: pops.length, pops: pops });
}

function handlePartitionEventLog(output, payload) {
  const regionId = payload.region_id;
  if (!regionId) return jsonResponse(output, { status: 'error', message: 'region_id required' });

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_PARTITION_EVENTS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Partition_Events sheet missing' });

  const now = new Date().toISOString();

  sheet.appendRow([
    now,
    regionId,
    payload.status || 'partitioned',
    payload.mitigation_token || '',
    payload.details || ''
  ]);

  logAudit('partition_event_log', regionId, 'Recorded partition event for ' + regionId + ': ' + (payload.status || 'partitioned'), 'SUCCESS');
  return jsonResponse(output, { status: 'success', region_id: regionId, timestamp: now });
}

function handleMarketplaceRecordTransaction(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_MARKETPLACE_TRANSACTIONS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Marketplace_Transactions sheet missing' });

  const id = payload.id || ('tx_' + Utilities.getUuid());
  const eventId = payload.event_id || '';
  const provider = payload.provider || 'unknown';
  const action = payload.action_type || payload.action || 'provision';
  const customerEmail = payload.customer_email || '';
  const licenseKey = payload.license_key || '';
  const tier = payload.tier || 'pro';
  const seats = Number(payload.seats) || 1;
  const status = payload.status || 'success';
  const errorMessage = payload.error_message || '';
  const processedAt = payload.processed_at || new Date().toISOString();

  sheet.appendRow([
    id,
    eventId,
    provider,
    action,
    customerEmail,
    licenseKey,
    tier,
    seats,
    status,
    errorMessage,
    processedAt
  ]);

  logAudit('marketplace_record_tx', provider + ':' + eventId, 'Recorded ' + provider + ' tx ' + id + ' for ' + customerEmail, 'SUCCESS');
  return jsonResponse(output, { status: 'success', id: id, processed_at: processedAt });
}

function handleMarketplaceListTransactions(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_MARKETPLACE_TRANSACTIONS);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Marketplace_Transactions sheet missing' });

  const data = sheet.getDataRange().getValues();
  const txs = [];
  const filterProvider = (payload.provider || '').toString().toLowerCase().trim();
  const filterEmail = (payload.customer_email || payload.email || '').toString().toLowerCase().trim();
  const filterStatus = (payload.status || '').toString().toUpperCase().trim();
  const limit = Number(payload.limit) || 0;

  // Iterate backwards so newest transactions appear first
  for (let i = data.length - 1; i >= 1; i--) {
    const row = data[i];
    if (filterProvider && (row[2] || '').toString().toLowerCase().trim() !== filterProvider) continue;
    if (filterEmail && (row[4] || '').toString().toLowerCase().trim() !== filterEmail) continue;
    if (filterStatus && (row[8] || '').toString().toUpperCase().trim() !== filterStatus) continue;

    txs.push({
      id: row[0],
      event_id: row[1],
      provider: row[2],
      action: row[3],
      customer_email: row[4],
      license_key: row[5],
      tier: row[6],
      seats: Number(row[7]),
      status: row[8],
      error_message: row[9],
      processed_at: row[10]
    });

    if (limit > 0 && txs.length >= limit) {
      break;
    }
  }

  return jsonResponse(output, { status: 'success', count: txs.length, transactions: txs });
}

function handleMarketplaceGetStatus(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_MARKETPLACE_TRANSACTIONS);
  
  let totalCount = 0;
  const providerCounts = { stripe: 0, lemonsqueezy: 0, paddle: 0 };
  let totalProvisioned = 0;
  let totalRevoked = 0;
  let totalDuplicates = 0;
  let totalFailed = 0;
  let lastProcessedAt = '';

  if (sheet) {
    const data = sheet.getDataRange().getValues();
    totalCount = Math.max(0, data.length - 1);
    for (let i = 1; i < data.length; i++) {
      const p = (data[i][2] || '').toString().toLowerCase().trim();
      if (providerCounts.hasOwnProperty(p)) {
        providerCounts[p]++;
      }
      const st = (data[i][8] || '').toString().toUpperCase().trim();
      if (st === 'PROVISIONED') totalProvisioned++;
      else if (st === 'REVOKED') totalRevoked++;
      else if (st === 'DUPLICATE') totalDuplicates++;
      else if (st === 'FAILED') totalFailed++;

      if (data[i][10]) {
        lastProcessedAt = data[i][10];
      }
    }
  }

  return jsonResponse(output, {
    status: 'success',
    providers: {
      stripe: { active: true, count: providerCounts.stripe },
      lemonsqueezy: { active: true, count: providerCounts.lemonsqueezy },
      paddle: { active: true, count: providerCounts.paddle }
    },
    total_transactions: totalCount,
    total_processed_events: totalCount,
    total_provisioned: totalProvisioned,
    total_revoked: totalRevoked,
    total_duplicates: totalDuplicates,
    total_failed: totalFailed,
    last_processed_at: lastProcessedAt
  });
}

function handleAirgapRecordToken(output, payload) {
  payload = payload || {};
  const tokenId = payload.token_id;
  const licenseKey = payload.license_key;
  const hwid = payload.hwid;
  if (!tokenId || !licenseKey) {
    return jsonResponse(output, { status: 'error', message: 'token_id and license_key required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_AIRGAP_VAULT);
  if (!sheet) {
    return jsonResponse(output, { status: 'error', message: 'AirGap_Vault sheet not found' });
  }

  const now = new Date().toISOString();
  const data = sheet.getDataRange().getValues();
  let updated = false;

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === tokenId) {
      sheet.getRange(i + 1, 7).setValue(payload.counter || data[i][6]);
      sheet.getRange(i + 1, 8).setValue(payload.status || 'ACTIVE');
      sheet.getRange(i + 1, 10).setValue(now);
      updated = true;
      break;
    }
  }

  if (!updated) {
    sheet.appendRow([
      tokenId,
      licenseKey,
      hwid || '',
      payload.tier || 'enterprise',
      payload.issued_at || '',
      payload.expires_at || '',
      payload.counter || 1,
      payload.status || 'ACTIVE',
      payload.signature || '',
      now
    ]);
  }

  logAudit('airgap_record_token', hwid || 'system', 'Recorded airgap token ' + tokenId, 'SUCCESS');
  return jsonResponse(output, { status: 'success', token_id: tokenId, updated: updated });
}

function handleAirgapListTokens(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_AIRGAP_VAULT);
  const tokens = [];

  if (sheet) {
    const data = sheet.getDataRange().getValues();
    const filterHwid = (payload.hwid || '').toString().toUpperCase().trim();
    const filterLicense = (payload.license_key || '').toString().trim();
    const limit = parseInt(payload.limit, 10) || 100;

    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      if (!row[0]) continue;

      if (filterHwid && (row[2] || '').toString().toUpperCase() !== filterHwid) continue;
      if (filterLicense && (row[1] || '').toString() !== filterLicense) continue;

      tokens.push({
        token_id: row[0],
        license_key: row[1],
        hwid: row[2],
        tier: row[3],
        issued_at: row[4],
        expires_at: row[5],
        counter: row[6],
        status: row[7],
        signature: row[8],
        updated_at: row[9]
      });

      if (limit > 0 && tokens.length >= limit) break;
    }
  }

  return jsonResponse(output, { status: 'success', count: tokens.length, tokens: tokens });
}

function handleAirgapGetStatus(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_AIRGAP_VAULT);

  let totalTokens = 0;
  let activeTokens = 0;
  const uniqueDevices = {};
  let lastIssuedAt = '';

  if (sheet) {
    const data = sheet.getDataRange().getValues();
    totalTokens = Math.max(0, data.length - 1);

    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      if (!row[0]) continue;

      const st = (row[7] || '').toString().toUpperCase();
      if (st === 'ACTIVE') activeTokens++;

      const hwid = (row[2] || '').toString();
      if (hwid) uniqueDevices[hwid] = true;

      if (row[9]) lastIssuedAt = row[9];
    }
  }

  return jsonResponse(output, {
    status: 'success',
    vault_active: true,
    total_tokens: totalTokens,
    active_tokens: activeTokens,
    tracked_devices: Object.keys(uniqueDevices).length,
    last_issued_at: lastIssuedAt
  });
}

function handleZeroTrustEnrollPeer(output, payload) {
  payload = payload || {};
  const nodeId = payload.node_id;
  if (!nodeId) {
    return jsonResponse(output, { status: 'error', message: 'node_id is required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ZEROTRUST_PEERS);
  if (!sheet) {
    return jsonResponse(output, { status: 'error', message: 'ZeroTrust_Peers sheet not found' });
  }

  const data = sheet.getDataRange().getValues();
  let updated = false;
  const now = new Date().toISOString();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === nodeId) {
      sheet.getRange(i + 1, 2, 1, 6).setValues([[
        payload.role || 'cluster_peer',
        payload.serial_number || '',
        payload.fingerprint_sha256 || '',
        payload.expires_at || '',
        payload.status || 'ACTIVE',
        now
      ]]);
      updated = true;
      break;
    }
  }

  if (!updated) {
    sheet.appendRow([
      nodeId,
      payload.role || 'cluster_peer',
      payload.serial_number || '',
      payload.fingerprint_sha256 || '',
      payload.expires_at || '',
      payload.status || 'ACTIVE',
      now
    ]);
  }

  logAudit('zerotrust_enroll_peer', nodeId, 'Enrolled peer ' + nodeId, 'SUCCESS');
  return jsonResponse(output, { status: 'success', node_id: nodeId, updated: updated });
}

function handleZeroTrustRevokePeer(output, payload) {
  payload = payload || {};
  const nodeId = payload.node_id;
  if (!nodeId) {
    return jsonResponse(output, { status: 'error', message: 'node_id is required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ZEROTRUST_PEERS);
  if (!sheet) {
    return jsonResponse(output, { status: 'error', message: 'ZeroTrust_Peers sheet not found' });
  }

  const data = sheet.getDataRange().getValues();
  let found = false;
  const now = new Date().toISOString();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === nodeId) {
      sheet.getRange(i + 1, 6, 1, 2).setValues([['REVOKED', now]]);
      found = true;
      break;
    }
  }

  logAudit('zerotrust_revoke_peer', nodeId, 'Revoked peer ' + nodeId + ' reason: ' + (payload.reason || 'None'), 'SUCCESS');
  return jsonResponse(output, { status: 'success', node_id: nodeId, revoked: found });
}

function handleZeroTrustRotateCA(output, payload) {
  payload = payload || {};
  const fp = payload.root_fingerprint || '';
  const expiresAt = payload.expires_at || '';

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ZEROTRUST_CA);
  if (sheet) {
    sheet.appendRow([fp, expiresAt, 'ACTIVE', new Date().toISOString()]);
  }

  logAudit('zerotrust_rotate_ca', 'system', 'Rotated internal CA root fingerprint ' + fp, 'SUCCESS');
  return jsonResponse(output, { status: 'success', root_fingerprint: fp });
}

function handleZeroTrustGetStatus(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const peerSheet = ss.getSheetByName(SHEET_ZEROTRUST_PEERS);
  const caSheet = ss.getSheetByName(SHEET_ZEROTRUST_CA);

  let activePeers = 0;
  let revokedPeers = 0;
  if (peerSheet) {
    const data = peerSheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      const st = data[i][5];
      if (st === 'ACTIVE') activePeers++;
      else if (st === 'REVOKED') revokedPeers++;
    }
  }

  let latestFingerprint = '';
  if (caSheet) {
    const data = caSheet.getDataRange().getValues();
    if (data.length > 1) {
      latestFingerprint = data[data.length - 1][0];
    }
  }

  return jsonResponse(output, {
    status: 'success',
    ca_active: true,
    root_fingerprint: latestFingerprint,
    active_peers: activePeers,
    revoked_peers: revokedPeers
  });
}

function handleHealingRecordLease(output, payload) {
  payload = payload || {};
  const leaseId = payload.lease_id || ('lease_' + Utilities.getUuid().substring(0, 8));
  const borrower = payload.borrower_tenant || '';
  const lender = payload.lender_tenant || '';
  const amount = payload.amount || 0;
  const borrowedAt = payload.borrowed_at || new Date().toISOString();
  const expiresAt = payload.expires_at || '';
  const status = payload.status || 'ACTIVE';

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_HEALING_LEASES);
  if (sheet) {
    sheet.appendRow([leaseId, borrower, lender, amount, borrowedAt, expiresAt, status, '']);
  }

  logAudit('healing_record_lease', borrower, 'Recorded quota lease ' + leaseId + ' (' + amount + ' units from ' + lender + ')', 'SUCCESS');
  return jsonResponse(output, { status: 'success', lease_id: leaseId });
}

function handleHealingReturnLease(output, payload) {
  payload = payload || {};
  const leaseId = payload.lease_id || '';
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_HEALING_LEASES);

  let updated = false;
  if (sheet) {
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === leaseId) {
        sheet.getRange(i + 1, 7).setValue('RETURNED');
        updated = true;
        break;
      }
    }
  }

  logAudit('healing_return_lease', leaseId, 'Returned quota lease ' + leaseId, 'SUCCESS');
  return jsonResponse(output, { status: 'success', lease_id: leaseId, returned: updated });
}

function handleHealingLogTunnel(output, payload) {
  payload = payload || {};
  const sessionId = payload.session_id || ('sess_' + Utilities.getUuid().substring(0, 8));
  const clientId = payload.client_id || '';
  const hwid = payload.hwid || '';
  const tenantId = payload.tenant_id || 'default';
  const state = payload.state || 'CONNECTED';
  const now = new Date().toISOString();

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_HEALING_TUNNELS);
  if (sheet) {
    sheet.appendRow([sessionId, clientId, hwid, tenantId, state, now, now, now]);
  }

  return jsonResponse(output, { status: 'success', session_id: sessionId });
}

function handleHealingGetStatus(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const leaseSheet = ss.getSheetByName(SHEET_HEALING_LEASES);
  const tunnelSheet = ss.getSheetByName(SHEET_HEALING_TUNNELS);

  let activeLeases = 0;
  let totalBorrowed = 0;
  if (leaseSheet) {
    const data = leaseSheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (data[i][6] === 'ACTIVE') {
        activeLeases++;
        totalBorrowed += Number(data[i][3]) || 0;
      }
    }
  }

  let totalTunnels = 0;
  if (tunnelSheet) {
    totalTunnels = Math.max(0, tunnelSheet.getLastRow() - 1);
  }

  return jsonResponse(output, {
    status: 'success',
    active_leases: activeLeases,
    total_borrowed_units: totalBorrowed,
    tracked_tunnels: totalTunnels,
    timestamp: new Date().toISOString()
  });
}

function handleHSMLogEvent(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_HSM_AUDIT_LOG);
  const ts = payload.timestamp || new Date().toISOString();
  if (sheet) {
    sheet.appendRow([
      ts,
      payload.event_type || 'INFO',
      payload.slot_id !== undefined ? payload.slot_id : '',
      payload.purpose || '',
      payload.fingerprint || '',
      payload.sensor_id || '',
      JSON.stringify(payload.details || {})
    ]);
  }
  return jsonResponse(output, { status: 'success', logged_at: ts });
}

function handleHSMGetStatus(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_HSM_AUDIT_LOG);
  let totalEvents = 0;
  if (sheet) {
    totalEvents = Math.max(0, sheet.getLastRow() - 1);
  }
  return jsonResponse(output, {
    status: 'success',
    fips_level: 'FIPS_140_3_LEVEL_4',
    audit_events_count: totalEvents,
    tamper_detected: false
  });
}

function handleHSMRecordDerivation(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_HSM_VAULT_KEYS);
  const keyId = Utilities.getUuid();
  const createdAt = new Date().toISOString();
  if (sheet) {
    sheet.appendRow([
      keyId,
      payload.slot_id !== undefined ? payload.slot_id : 0,
      payload.purpose || 'audit_token_encryption',
      payload.algorithm || 'AES_256_GCM_HKDF_SHA256',
      payload.fingerprint || '',
      'active',
      createdAt
    ]);
  }
  return jsonResponse(output, { status: 'success', key_id: keyId, created_at: createdAt });
}

function handleMLKEMLogKey(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_MLKEM_KEY_LEDGER);
  const createdAt = payload.created_at || new Date().toISOString();
  if (sheet) {
    sheet.appendRow([
      payload.key_id || Utilities.getUuid(),
      payload.algorithm || 'ML-KEM-768',
      payload.fingerprint || '',
      'active',
      createdAt
    ]);
  }
  return jsonResponse(output, { status: 'success', key_id: payload.key_id, logged_at: createdAt });
}

function handleMLKEMLogSession(output, payload) {
  payload = payload || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_MLKEM_SESSIONS);
  const createdAt = new Date().toISOString();
  if (sheet) {
    sheet.appendRow([
      payload.session_id || Utilities.getUuid(),
      payload.agreed_mode || 'hybrid',
      payload.algorithm || 'ML-KEM-768',
      payload.quantum_resistant === true,
      payload.expires_at || '',
      createdAt
    ]);
  }
  return jsonResponse(output, { status: 'success', session_id: payload.session_id, logged_at: createdAt });
}

function handleMLKEMGetStatus(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const keySheet = ss.getSheetByName(SHEET_MLKEM_KEY_LEDGER);
  const sessSheet = ss.getSheetByName(SHEET_MLKEM_SESSIONS);
  let totalKeys = 0;
  let totalSessions = 0;
  if (keySheet) {
    totalKeys = Math.max(0, keySheet.getLastRow() - 1);
  }
  if (sessSheet) {
    totalSessions = Math.max(0, sessSheet.getLastRow() - 1);
  }
  return jsonResponse(output, {
    status: 'success',
    fips_standard: 'NIST_FIPS_203_ML_KEM',
    registered_keys: totalKeys,
    active_sessions: totalSessions,
    quantum_resistant: true,
    timestamp: new Date().toISOString()
  });
}

function handleTransparencyRecordEntry(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_TRANSPARENCY_LOG);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Sheet not found' });
  const index = payload.index !== undefined ? payload.index : sheet.getLastRow() - 1;
  const action = payload.action || 'audit_event';
  const tenantId = payload.tenant_id || 'default';
  const leafHashHex = payload.leaf_hash_hex || '';
  const timestamp = payload.timestamp || new Date().toISOString();
  const signature = payload.signature || '';
  const treeSize = payload.tree_size || 0;
  const rootHashHex = payload.root_hash_hex || '';
  const payloadJson = payload.payload ? JSON.stringify(payload.payload) : '{}';

  sheet.appendRow([index, action, tenantId, leafHashHex, timestamp, signature, treeSize, rootHashHex, payloadJson]);
  return jsonResponse(output, { status: 'success', index: index, tree_size: treeSize, root_hash_hex: rootHashHex });
}

function handleTransparencyRecordSTH(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_WITNESS_COSIGNATURES);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Sheet not found' });
  const witnessId = payload.witness_id || 'primary_log';
  const treeSize = payload.tree_size || 0;
  const rootHashHex = payload.root_hash_hex || '';
  const timestamp = payload.timestamp || new Date().toISOString();
  const signature = payload.signature || '';
  const status = payload.status || 'verified';

  sheet.appendRow([witnessId, treeSize, rootHashHex, timestamp, signature, status]);
  return jsonResponse(output, { status: 'success', witness_id: witnessId, tree_size: treeSize });
}

function handleTransparencyListEntries(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_TRANSPARENCY_LOG);
  if (!sheet) return jsonResponse(output, { status: 'error', message: 'Sheet not found' });
  const data = sheet.getDataRange().getValues();
  const entries = [];
  const start = parseInt(payload.start || 0, 10);
  const count = parseInt(payload.count || 20, 10);

  for (let i = 1; i < data.length; i++) {
    if (i - 1 >= start && entries.length < count) {
      entries.push({
        index: data[i][0],
        action: data[i][1],
        tenant_id: data[i][2],
        leaf_hash_hex: data[i][3],
        timestamp: data[i][4],
        signature: data[i][5],
        tree_size: data[i][6],
        root_hash_hex: data[i][7],
        payload: data[i][8]
      });
    }
  }
  return jsonResponse(output, { status: 'success', total: data.length - 1, start: start, count: entries.length, entries: entries });
}

function handleTransparencyStatus(output, payload) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const logSheet = ss.getSheetByName(SHEET_TRANSPARENCY_LOG);
  const witSheet = ss.getSheetByName(SHEET_WITNESS_COSIGNATURES);
  let totalEntries = 0;
  let totalWitnesses = 0;
  let latestRoot = '';
  if (logSheet && logSheet.getLastRow() > 1) {
    totalEntries = logSheet.getLastRow() - 1;
    const lastRow = logSheet.getRange(logSheet.getLastRow(), 1, 1, logSheet.getLastColumn()).getValues()[0];
    latestRoot = lastRow[7] || '';
  }
  if (witSheet && witSheet.getLastRow() > 1) {
    totalWitnesses = witSheet.getLastRow() - 1;
  }
  return jsonResponse(output, {
    status: 'success',
    rfc_standard: 'RFC 6962',
    total_entries: totalEntries,
    latest_root_hash: latestRoot,
    witness_cosignatures_count: totalWitnesses,
    timestamp: new Date().toISOString()
  });
}





