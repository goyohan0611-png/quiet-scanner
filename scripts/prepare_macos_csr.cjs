// Prepare an encrypted signing key and public CSR on Windows. No Apple login,
// certificate issuance or credential upload is performed by this command.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
if (process.platform !== 'win32') throw Error('This helper is for Windows.');
const openssl = process.env.QUIET_OPENSSL || 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe';
const folder = path.join(process.env.LOCALAPPDATA, 'QuietScannerSigning');
const key = path.join(folder, 'developer-id-application.key.pem');
const passwordFile = path.join(folder, 'signing-password.dpapi');
const csr = path.join(folder, 'QuietScanner-DeveloperID.certSigningRequest');
function run(file, args, input) {
  try { return execFileSync(file, args, { input, encoding: 'utf8', windowsHide: true, stdio: ['pipe','pipe','pipe'] }); }
  catch (_) { throw Error(`Signing preparation failed at ${path.basename(file)}. Existing keys were not replaced.`); }
}
function powershell(script, input) {
  // A Node process started in PowerShell 7 can inherit its incompatible module
  // path. Import the Windows PowerShell security module by its own exact path.
  const prefix = "$ErrorActionPreference = 'Stop'; Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1') -ErrorAction Stop; ";
  return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', prefix+script], input).trim();
}
if (!fs.existsSync(openssl)) throw Error('Install Git for Windows (OpenSSL), or set QUIET_OPENSSL to its executable.');
fs.mkdirSync(folder, { recursive: true });
const sid = powershell('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value');
if (!/^S-1-(\d+-)+\d+$/.test(sid)) throw Error('Cannot determine the Windows signing user.');
run('icacls.exe', [folder, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F']);
if (fs.existsSync(key) !== fs.existsSync(passwordFile)) throw Error('Incomplete signing key files. Keep them for recovery; do not overwrite them.');
let password;
if (fs.existsSync(key)) {
  const protectedPassword = fs.readFileSync(passwordFile, 'utf8');
  password = powershell("$s = ConvertTo-SecureString ([Console]::In.ReadToEnd()); (New-Object System.Net.NetworkCredential('', $s)).Password", protectedPassword);
} else {
  password = crypto.randomBytes(32).toString('base64');
  const protectedPassword = powershell('ConvertTo-SecureString ([Console]::In.ReadToEnd()) -AsPlainText -Force | ConvertFrom-SecureString', password);
  fs.writeFileSync(passwordFile, protectedPassword, { flag: 'wx' });
  run(openssl, ['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-aes-256-cbc','-pass','stdin','-out',key], password+'\n');
}
if (!fs.existsSync(csr)) {
  run(openssl, ['req','-new','-sha256','-key',key,'-passin','stdin','-subj','/CN=Quiet Scanner Developer ID/','-out',csr], password+'\n');
}
if (!fs.readFileSync(key,'utf8').startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')) throw Error('The signing key must be encrypted.');
run(openssl, ['req','-in',csr,'-noout','-verify']);
const publicKey = run(openssl, ['pkey','-in',key,'-passin','stdin','-pubout'], password+'\n');
const requestedKey = run(openssl, ['req','-in',csr,'-noout','-pubkey']);
if (publicKey.trim() !== requestedKey.trim()) throw Error('The CSR does not match the encrypted signing key.');
console.log(JSON.stringify({csrPath:csr,requestVerified:true,keyEncrypted:true,passwordProtectedByWindows:true,uploaded:false},null,2));
