/**
 * Sheet-License-Broker (Google Apps Script Backend)
 * 
 * Provides serverless user authentication, license validation with HWID binding,
 * and key-value database storage using Google Sheets as a free backend.
 */

const SHEET_USERS = 'Users';
const SHEET_LICENSES = 'Licenses';
const SHEET_DATABASE = 'KV_Database';

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

      case 'db_put':
        return handleDBPut(output, payload);

      case 'db_get':
        return handleDBGet(output, payload);

      default:
        return jsonResponse(output, { status: 'error', message: 'Unknown action: ' + action });
    }
  } catch (err) {
    return jsonResponse(output, { status: 'error', message: err.toString() });
  }
}

function initSheets() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  if (!ss.getSheetByName(SHEET_USERS)) {
    const s = ss.insertSheet(SHEET_USERS);
    s.appendRow(['user_id', 'username', 'password_hash', 'salt', 'role', 'created_at']);
    s.getRange(1, 1, 1, 6).setFontWeight('bold');
  }

  if (!ss.getSheetByName(SHEET_LICENSES)) {
    const s = ss.insertSheet(SHEET_LICENSES);
    s.appendRow(['license_key', 'hwid_bound', 'max_devices', 'status', 'expires_at', 'created_at']);
    s.getRange(1, 1, 1, 6).setFontWeight('bold');
  }

  if (!ss.getSheetByName(SHEET_DATABASE)) {
    const s = ss.insertSheet(SHEET_DATABASE);
    s.appendRow(['collection', 'doc_id', 'payload_json', 'updated_at']);
    s.getRange(1, 1, 1, 4).setFontWeight('bold');
  }
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
  return jsonResponse(output, { status: 'success', user_id: userId, username: username });
}

function handleLogin(output, payload) {
  const username = payload.username;
  const password = payload.password;

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_USERS);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === username) {
      const salt = data[i][3];
      const storedHash = data[i][2];
      const computedHash = hashString(password + salt);

      if (storedHash === computedHash) {
        return jsonResponse(output, { status: 'success', user_id: data[i][0], username: username, role: data[i][4] });
      } else {
        return jsonResponse(output, { status: 'error', message: 'Invalid credentials' });
      }
    }
  }

  return jsonResponse(output, { status: 'error', message: 'User not found' });
}

function handleCreateLicense(output, payload) {
  const key = payload.license_key || ('KEY-' + Utilities.getUuid().substring(0, 8).toUpperCase());
  const maxDevices = payload.max_devices || 1;
  const days = payload.days || 30;

  const expDate = new Date();
  expDate.setDate(expDate.getDate() + Number(days));

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_LICENSES);
  sheet.appendRow([key, '', maxDevices, 'ACTIVE', expDate.toISOString(), new Date().toISOString()]);

  return jsonResponse(output, { status: 'success', license_key: key, expires_at: expDate.toISOString() });
}

function handleVerifyLicense(output, payload) {
  const key = payload.license_key;
  const hwid = payload.hwid || '';

  if (!key) {
    return jsonResponse(output, { status: 'error', message: 'License key required' });
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_LICENSES);
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === key) {
      const boundHWID = data[i][1];
      const status = data[i][3];
      const expiresAt = new Date(data[i][4]);

      if (status !== 'ACTIVE') {
        return jsonResponse(output, { status: 'error', message: 'License is ' + status });
      }
      if (new Date() > expiresAt) {
        return jsonResponse(output, { status: 'error', message: 'License expired on ' + expiresAt.toISOString() });
      }

      // First-time machine bind
      if (!boundHWID && hwid) {
        sheet.getRange(i + 1, 2).setValue(hwid);
        return jsonResponse(output, { status: 'success', verified: true, hwid_bound: hwid, message: 'License activated and bound to device' });
      }

      // Check device match
      if (boundHWID && hwid && boundHWID !== hwid) {
        return jsonResponse(output, { status: 'error', message: 'Device mismatch: bound to another HWID' });
      }

      return jsonResponse(output, { status: 'success', verified: true, hwid_bound: boundHWID, expires_at: expiresAt.toISOString() });
    }
  }

  return jsonResponse(output, { status: 'error', message: 'Invalid license key' });
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
