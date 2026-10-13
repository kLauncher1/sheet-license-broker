# Google Apps Script Backend & Clasp Deployment Guide

This directory houses the serverless Google Apps Script engine that turns Google Sheets into a high-performance, cost-free persistent backend for `sheet-license-broker`.

## Components

- `Code.gs`: The core Apps Script logic handling `doPost` and `doGet` requests, table initialization, salted SHA-256 password hashing, device HWID binding, and NoSQL key-value CRUD operations.
- `appsscript.json`: Project manifest specifying execution runtime (`V8`) and authorization scopes.
- `.clasp.json.example`: Template configuration for the Google Apps Script Clasp CLI tool.

---

## Deployment Options

### Option 1: Manual Setup via Google Sheets UI (3 Minutes)

1. Open [Google Sheets](https://sheets.new) and create a new blank spreadsheet.
2. In the top toolbar, click **Extensions > Apps Script**.
3. Replace the default `Code.gs` content with [`gas/Code.gs`](file:///gas/Code.gs).
4. In the left panel, click **Project Settings** (gear icon) and check **"Show 'appsscript.json' manifest file in editor"**.
5. Paste the contents of [`gas/appsscript.json`](file:///gas/appsscript.json) into `appsscript.json`.
6. Click **Deploy > New deployment**:
   - **Type**: Web app
   - **Description**: `sheet-license-broker-v0.2.0`
   - **Execute as**: `Me (your Google email)`
   - **Who has access**: `Anyone`
7. Click **Deploy**, authorize permissions, and copy the **Web app URL** (`https://script.google.com/macros/s/.../exec`).
8. Pass this URL to your environment variable:
   ```bash
   export GAS_WEBAPP_URL="https://script.google.com/macros/s/.../exec"
   ```

---

## Option 2: Programmatic Deployment via Clasp CLI

The `@google/clasp` tool allows you to push and deploy Google Apps Script directly from your command line.

### Prerequisites

Install the Clasp CLI globally or run it via npx:

```bash
npm install -g @google/clasp
```

Log in to your Google Account:

```bash
clasp login
```

### Initializing a Project

If you have an existing script attached to a Google Sheet:

```bash
cd gas
cp .clasp.json.example .clasp.json
# Edit .clasp.json and enter your scriptId
clasp pull
```

Or create a new standalone project:

```bash
cd gas
clasp create --title "Sheet-License-Broker" --type sheets
```

### Deploying the Web App

Push local changes:

```bash
clasp push
```

Create a versioned deployment as a Web App:

```bash
clasp deploy --description "Production Deployment v0.2.0"
```

List deployments to obtain your Web app URL:

```bash
clasp deployments
```

Once deployed, set `GAS_WEBAPP_URL` in your environment to activate the live Google Sheets gateway.
