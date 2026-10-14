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
    { name: SHEET_ATTESTATIONS, cols: ['timestamp', 'license_key', 'hwid', 'attestation_type', 'trust_level', 'pcr_digest', 'tamper_score', 'details'] }
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
