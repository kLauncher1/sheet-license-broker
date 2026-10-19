import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
/**
 * Resolves a stable, deterministic hardware identifier for the current host machine.
 * Supports Windows, Linux, and macOS without external package dependencies.
 */
export function getMachineHwid() {
    const platform = os.platform();
    const rawParts = [];
    try {
        if (platform === 'win32') {
            // 1. Try querying Windows Registry MachineGuid via reg.exe
            try {
                const out = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { timeout: 2500, stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf8' });
                const match = out.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/i);
                if (match && match[1]) {
                    rawParts.push(match[1].trim());
                }
            }
            catch { }
            // 2. Try PowerShell ComputerSystemProduct UUID fallback
            if (rawParts.length === 0) {
                try {
                    const out = execSync('powershell -NoProfile -Command "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"', { timeout: 2500, stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf8' });
                    if (out && out.trim().length > 8) {
                        rawParts.push(out.trim());
                    }
                }
                catch { }
            }
        }
        else if (platform === 'linux') {
            const candidates = ['/etc/machine-id', '/var/lib/dbus/machine-id', '/sys/class/dmi/id/product_uuid'];
            for (const file of candidates) {
                if (existsSync(file)) {
                    try {
                        const content = readFileSync(file, 'utf8').trim();
                        if (content) {
                            rawParts.push(content);
                            break;
                        }
                    }
                    catch { }
                }
            }
        }
        else if (platform === 'darwin') {
            try {
                const out = execSync('ioreg -rd1 -c IOPlatformExpertDevice', {
                    timeout: 2500,
                    stdio: ['ignore', 'pipe', 'ignore'],
                    encoding: 'utf8',
                });
                const match = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
                if (match && match[1]) {
                    rawParts.push(match[1].trim());
                }
            }
            catch { }
        }
    }
    catch { }
    // Fallback hardware attributes
    try {
        rawParts.push(os.hostname());
        rawParts.push(os.arch());
        const cpus = os.cpus();
        if (cpus.length > 0) {
            rawParts.push(cpus[0].model);
        }
        const net = os.networkInterfaces();
        for (const iface of Object.values(net)) {
            if (iface) {
                for (const addr of iface) {
                    if (!addr.internal && addr.mac && addr.mac !== '00:00:00:00:00:00') {
                        rawParts.push(addr.mac);
                        break;
                    }
                }
            }
        }
    }
    catch { }
    const seed = rawParts.filter(Boolean).join('|') || 'SHEET-LICENSE-FALLBACK-SEED';
    const digest = createHash('sha256').update(seed, 'utf8').digest('hex').toUpperCase();
    return `HWID-${digest.slice(0, 4)}-${digest.slice(4, 8)}-${digest.slice(8, 12)}-${digest.slice(12, 16)}`;
}
//# sourceMappingURL=hwid.js.map