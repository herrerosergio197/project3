/**
 * server.js — SysLog Monitor + SIEM
 * Windows Server 2016 · HTTPS puerto 443
 * Arrancar: node server.js
 */

const express   = require('express');
const https     = require('https');
const http      = require('http');
const fs        = require('fs');
const os        = require('os');
const path      = require('path');
const mysql     = require('mysql2/promise');
const bcrypt    = require('bcryptjs');
const cors      = require('cors');
const { exec }  = require('child_process');

const app = express();
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ─── CONFIGURACIÓN ────────────────────────────────────────────
const DB_CONFIG = {
  host:     'localhost',
  user:     'root',
  password: '',
  database: 'sistema_logs',
};
const SSL_CERT = path.join(__dirname, 'server.crt');
const SSL_KEY  = path.join(__dirname, 'server.key');


// ─── HELPER IPv6 → IPv4 ───────────────────────────────────────
function ipv4(ip) {
  if (!ip) return '';
  ip = ip.trim();
  if (ip.startsWith('::ffff:') || ip.startsWith('::FFFF:')) return ip.substring(7);
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

// ─── POOL MySQL ───────────────────────────────────────────────
let pool;
async function getPool() {
  if (!pool) pool = mysql.createPool(DB_CONFIG);
  return pool;
}

// ─── HELPER PowerShell ────────────────────────────────────────
function runPowerShell(lines, callback) {
  const tmp = path.join(os.tmpdir(), 'syslog_' + Date.now() + '.ps1');
  fs.writeFile(tmp, lines.join('\r\n'), 'utf8', (err) => {
    if (err) return callback(err, '', '');
    exec(
      'powershell.exe -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { maxBuffer: 10 * 1024 * 1024, timeout: 20000 },
      (err2, stdout, stderr) => {
        fs.unlink(tmp, () => {});
        callback(err2, stdout || '', stderr || '');
      }
    );
  });
}

// ─── LOGIN ────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  try {
    const db = await getPool();
    const [rows] = await db.execute(
      'SELECT id, usuario, password_hash, nombre, rol FROM usuarios WHERE usuario = ? AND activo = 1',
      [usuario]
    );
    if (rows.length === 0) {
      try { await db.execute('INSERT INTO log_accesos (usuario_id, ip, accion) VALUES (NULL, ?, ?)', [ipv4(req.ip), 'login_fail']); } catch(e) {}
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      try { await db.execute('INSERT INTO log_accesos (usuario_id, ip, accion) VALUES (NULL, ?, ?)', [ipv4(req.ip), 'login_fail']); } catch(e) {}
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
    await db.execute(
      'INSERT INTO log_accesos (usuario_id, ip, accion) VALUES (?, ?, ?)',
      [user.id, ipv4(req.ip), 'login']
    );
    try {
      await db.execute(
        'DELETE FROM log_accesos WHERE ip=? AND accion="login_fail" AND fecha >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)',
        [req.ip]
      );
    } catch(e) {}
    res.json({ ok: true, usuario: { id: user.id, nombre: user.nombre, rol: user.rol } });
  } catch (err) {
    console.error('[LOGIN ERROR]', err.message);
    res.status(500).json({ error: 'Error de servidor: ' + err.message });
  }
});

// ─── LOGS DEL SISTEMA ─────────────────────────────────────────
app.get('/api/logs/sistema', (req, res) => {
  const tipo   = req.query.tipo || 'syslog';
  const lineas = Math.min(parseInt(req.query.lineas) || 200, 1000);
  const mapLogName = { syslog:'System', auth:'Security', kern:'System', dmesg:'System', boot:'System', messages:'Application' };
  const logName = mapLogName[tipo] || 'System';
  const scriptLines = [
    '$ErrorActionPreference = "SilentlyContinue"',
    '$output = New-Object System.Collections.ArrayList',
    '$eventos = Get-EventLog -LogName "' + logName + '" -Newest ' + lineas + ' 2>$null',
    'foreach ($e in $eventos) {',
    '    $ts  = $e.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")',
    '    $lvl = $e.EntryType.ToString()',
    '    $src = $e.Source',
    '    $msg = ($e.Message -replace "[\\r\\n\\t]+"," ").Trim()',
    '    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }',
    '    $linea = "[$ts] [$lvl] $src : $msg"',
    '    [void]$output.Add($linea)',
    '}',
    '$output',
  ];
  runPowerShell(scriptLines, (err, stdout, stderr) => {
    if (!stdout.trim()) return res.json({ lineas: [], fuente: 'Windows Event Log - ' + logName, error: stderr || 'Sin resultados' });
    const lineasArr = stdout.split('\n').map(l => l.trim()).filter(l => l.startsWith('[')).map(raw => ({ raw }));
    res.json({ lineas: lineasArr, fuente: 'Windows Event Log - ' + logName });
  });
});

// ─── LOGS DE RED ──────────────────────────────────────────────
app.get('/api/logs/red', (req, res) => {
  const lineas = Math.min(parseInt(req.query.lineas) || 100, 500);
  const scriptLines = [
    '$ErrorActionPreference = "SilentlyContinue"',
    '$output = New-Object System.Collections.ArrayList',
    '$conns = Get-NetTCPConnection 2>$null | Select-Object -First ' + lineas,
    'foreach ($c in $conns) {',
    '    $local  = $c.LocalAddress + ":" + $c.LocalPort',
    '    $remote = $c.RemoteAddress + ":" + $c.RemotePort',
    '    $state  = $c.State',
    '    $ts     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")',
    '    [void]$output.Add("[$ts] [NET] $local  -->  $remote  [$state]")',
    '}',
    'if ($output.Count -eq 0) {',
    '    $netstat = netstat -an 2>$null',
    '    foreach ($line in $netstat) { [void]$output.Add($line) }',
    '}',
    '$output',
  ];
  runPowerShell(scriptLines, (err, stdout) => {
    const lineasArr = stdout.split('\n').map(l => l.trim()).filter(l => l.length > 5).map(raw => ({ raw }));
    res.json({ lineas: lineasArr, fuente: 'Get-NetTCPConnection / netstat' });
  });
});

// ─── LOGS MySQL ───────────────────────────────────────────────
app.get('/api/logs/mysql', (req, res) => {
  const tipo   = req.query.tipo || 'general';
  const lineas = Math.min(parseInt(req.query.lineas) || 200, 1000);
  const dataDir = 'C:\\ProgramData\\MySQL\\MySQL Server 8.0\\Data\\';
  const rutas = {
    general: [
      dataDir + 'mysql_general.log',
      dataDir + 'general.log',
      dataDir + require('os').hostname().toLowerCase() + '.log',
      'C:\\ProgramData\\MySQL\\Data\\mysql_general.log',
      'C:\\ProgramData\\MySQL\\MySQL Server 5.7\\Data\\mysql_general.log',
    ],
    slow: [
      dataDir + 'mysql_slow.log',
      dataDir + 'slow.log',
      dataDir + require('os').hostname().toLowerCase() + '-slow.log',
      'C:\\ProgramData\\MySQL\\Data\\mysql_slow.log',
      'C:\\ProgramData\\MySQL\\MySQL Server 5.7\\Data\\mysql_slow.log',
    ],
  };
  const candidatos = rutas[tipo] || rutas.general;
  const scriptLines = [
    '$ErrorActionPreference = "SilentlyContinue"',
    '$rutas = @(' + candidatos.map(r => '"' + r.replace(/\\/g, '\\\\') + '"').join(', ') + ')',
    '$archivo = $null',
    'foreach ($r in $rutas) { if (Test-Path $r) { $archivo = $r; break } }',
    'if (-not $archivo) { Write-Output "ERROR|Log MySQL no encontrado. Activa general_log en my.ini"; exit }',
    'Write-Output ("SOURCE|" + $archivo)',
    '$lineas = Get-Content $archivo -Tail ' + lineas + ' -ErrorAction SilentlyContinue',
    'foreach ($l in $lineas) { Write-Output ("LINE|" + $l) }',
  ];
  runPowerShell(scriptLines, (err, stdout) => {
    const lines  = stdout.split('\n').map(l => l.trim()).filter(Boolean);
    let fuente   = 'MySQL ' + tipo + ' log';
    let error    = null;
    const result = [];
    lines.forEach(line => {
      if (line.startsWith('SOURCE|'))      fuente = line.substring(7);
      else if (line.startsWith('ERROR|'))  error  = line.substring(6);
      else if (line.startsWith('LINE|'))   result.push({ raw: line.substring(5) });
    });
    res.json({ lineas: result, fuente, error: error || undefined });
  });
});

// ─── LOGS BD (auditoría) ──────────────────────────────────────
app.get('/api/logs/bd', async (req, res) => {
  const limite = parseInt(req.query.lineas) || 100;
  try {
    const db = await getPool();
    const [rows] = await db.execute(
      'SELECT l.*, u.usuario FROM log_accesos l LEFT JOIN usuarios u ON l.usuario_id = u.id ORDER BY l.fecha DESC LIMIT ' + limite
    );
    res.json({
      lineas: rows.map(r => ({ raw: '[' + r.fecha + '] [INFO] ' + (r.usuario || 'desconocido') + ' | IP: ' + r.ip + ' | ' + r.accion })),
      fuente: 'MySQL - tabla log_accesos'
    });
  } catch (err) {
    res.status(500).json({ lineas: [], error: err.message });
  }
});

// ─── STATS ────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  res.json({ ok: true, plataforma: 'Windows Server 2016', uptime: process.uptime() });
});

// ─── SYSTEM INFO ──────────────────────────────────────────────
app.get('/api/sysinfo', (req, res) => {
  const scriptLines = [
    '$ErrorActionPreference = "SilentlyContinue"',
    '$cpu      = Get-WmiObject Win32_Processor | Select-Object -First 1',
    '$cpuLoad  = [int](Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average',
    '$os       = Get-WmiObject Win32_OperatingSystem',
    '$ramTotal = [math]::Round([long]$os.TotalVisibleMemorySize / 1MB, 2)',
    '$ramFree  = [math]::Round([long]$os.FreePhysicalMemory / 1MB, 2)',
    '$ramUsed  = [math]::Round($ramTotal - $ramFree, 2)',
    '$ramPct   = if ($ramTotal -gt 0) { [math]::Round(($ramUsed / $ramTotal) * 100, 1) } else { 0 }',
    '$disk     = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=\'C:\'"',
    '$diskTotal= [math]::Round([long]$disk.Size / 1GB, 2)',
    '$diskFree = [math]::Round([long]$disk.FreeSpace / 1GB, 2)',
    '$diskUsed = [math]::Round($diskTotal - $diskFree, 2)',
    '$diskPct  = if ($diskTotal -gt 0) { [math]::Round(($diskUsed / $diskTotal) * 100, 1) } else { 0 }',
    '$gpu      = Get-WmiObject Win32_VideoController | Select-Object -First 1',
    '$gpuName  = if ($gpu) { $gpu.Name } else { "N/A" }',
    '$gpuRam   = if ($gpu -and [long]$gpu.AdapterRAM -gt 0) { [math]::Round([long]$gpu.AdapterRAM / 1GB, 2) } else { 0 }',
    '$cs       = Get-WmiObject Win32_ComputerSystem',
    '$bios     = Get-WmiObject Win32_BIOS',
    '$nic      = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -First 1',
    '$ip       = if ($nic -and $nic.IPAddress)  { $nic.IPAddress[0] }  else { "N/A" }',
    '$mac      = if ($nic -and $nic.MACAddress) { $nic.MACAddress }    else { "N/A" }',
    '$uptime   = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)',
    '$uptimeStr = ("{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)',
    'Write-Output ("CPU_LOAD|"   + $cpuLoad)',
    'Write-Output ("CPU_NAME|"   + $cpu.Name.Trim())',
    'Write-Output ("CPU_CORES|"  + $cpu.NumberOfCores)',
    'Write-Output ("RAM_TOTAL|"  + $ramTotal)',
    'Write-Output ("RAM_USED|"   + $ramUsed)',
    'Write-Output ("RAM_PCT|"    + $ramPct)',
    'Write-Output ("DISK_TOTAL|" + $diskTotal)',
    'Write-Output ("DISK_USED|"  + $diskUsed)',
    'Write-Output ("DISK_PCT|"   + $diskPct)',
    'Write-Output ("GPU_NAME|"   + $gpuName)',
    'Write-Output ("GPU_RAM|"    + $gpuRam)',
    'Write-Output ("HOSTNAME|"   + $env:COMPUTERNAME)',
    'Write-Output ("DOMAIN|"     + $cs.Domain)',
    'Write-Output ("SERIAL|"     + $bios.SerialNumber.Trim())',
    'Write-Output ("MODEL|"      + $cs.Model.Trim())',
    'Write-Output ("IP|"         + $ip)',
    'Write-Output ("MAC|"        + $mac)',
    'Write-Output ("UPTIME|"     + $uptimeStr)',
  ];
  runPowerShell(scriptLines, (err, stdout) => {
    const data = {};
    stdout.split('\n').forEach(line => {
      line = line.trim();
      const idx = line.indexOf('|');
      if (idx === -1) return;
      data[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
    });
    const num = k => parseFloat(data[k]) || 0;
    res.json({
      cpuLoad: num('CPU_LOAD'), cpuName: data['CPU_NAME'] || '—', cpuCores: num('CPU_CORES'),
      ramTotal: num('RAM_TOTAL'), ramUsed: num('RAM_USED'), ramPct: num('RAM_PCT'),
      diskTotal: num('DISK_TOTAL'), diskUsed: num('DISK_USED'), diskPct: num('DISK_PCT'),
      gpuName: data['GPU_NAME'] || 'N/A', gpuRam: num('GPU_RAM'),
      hostname: data['HOSTNAME'] || '—', domain: data['DOMAIN'] || '—',
      serial: data['SERIAL'] || '—', model: data['MODEL'] || '—',
      ip: data['IP'] || '—', mac: data['MAC'] || '—', uptime: data['UPTIME'] || '—',
    });
  });
});

// ─── USUARIO AUTENTICADO ──────────────────────────────────────
app.get('/api/sysinfo/usuario', (req, res) => {
  const scriptLines = [
    '$ErrorActionPreference = "SilentlyContinue"',
    '$out = New-Object System.Collections.ArrayList',
    'try { $w = (whoami).Trim(); [void]$out.Add("WHOAMI|" + $w) } catch { [void]$out.Add("WHOAMI|error") }',
    'try { $cs = Get-WmiObject Win32_ComputerSystem; if ($cs.UserName) { [void]$out.Add("USER|" + $cs.UserName) } } catch {}',
    'try {',
    '  $qs = & query user 2>$null',
    '  foreach ($line in $qs) {',
    '    if ($line -match "Active|Activ") {',
    '      $parts = $line.Trim() -split "\\s+"',
    '      [void]$out.Add("SESSION|" + $parts[0] + "|Active")',
    '    }',
    '  }',
    '} catch {}',
    'try {',
    '  $wmi  = Get-WmiObject Win32_LoggedOnUser -ErrorAction SilentlyContinue',
    '  $seen = @{}',
    '  foreach ($l in $wmi) {',
    '    try {',
    '      $q   = [char]34',
    '      $pat = $q + "([^" + $q + "]+)" + $q',
    '      if ($l.Antecedent -match ("Name=" + $pat)) {',
    '        $acc = $Matches[1]',
    '        if ($acc -notmatch "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM|UMFD)" -and -not $seen[$acc]) {',
    '          $seen[$acc] = $true',
    '          if ($l.Dependent -match ("LogonId=" + $pat)) {',
    '            [void]$out.Add("LOGON|" + $acc + "|" + $Matches[1])',
    '          }',
    '        }',
    '      }',
    '    } catch {}',
    '  }',
    '} catch {}',
    '$out',
  ];
  runPowerShell(scriptLines, (err, stdout) => {
    const lines    = stdout.split('\n').map(l => l.trim()).filter(Boolean);
    const whoami   = (lines.find(l => l.startsWith('WHOAMI|'))  || 'WHOAMI|desconocido').substring(7);
    const user     = (lines.find(l => l.startsWith('USER|'))    || 'USER|desconocido').substring(5);
    const sessions = lines.filter(l => l.startsWith('SESSION|')).map(l => {
      const p = l.split('|'); return { usuario: (p[1] || '').replace(/^>/, ''), estado: p[2] || '' };
    });
    const logons   = lines.filter(l => l.startsWith('LOGON|')).map(l => {
      const p = l.split('|'); return { usuario: p[1] || '', sesion: p[2] || '' };
    });
    res.json({ whoami, user, sessions, logons });
  });
});

// ─── HISTÓRICO DE RECURSOS ────────────────────────────────────
const resourceHistory = { samples: [], maxSamples: 10080 };

function recogerMuestra() {
  const scriptLines = [
    '$ErrorActionPreference = "SilentlyContinue"',
    '$cpu  = [int](Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average',
    '$os   = Get-WmiObject Win32_OperatingSystem',
    '$ramT = [long]$os.TotalVisibleMemorySize',
    '$ramF = [long]$os.FreePhysicalMemory',
    '$ramP = if ($ramT -gt 0) { [math]::Round((($ramT-$ramF)/$ramT)*100,1) } else { 0 }',
    '$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=\'C:\'"',
    '$diskP= if ($disk.Size -gt 0) { [math]::Round((($disk.Size-$disk.FreeSpace)/$disk.Size)*100,1) } else { 0 }',
    '$gpu  = Get-WmiObject Win32_VideoController | Select-Object -First 1',
    '$gpuR = if ($gpu -and [long]$gpu.AdapterRAM -gt 0) { [math]::Round([long]$gpu.AdapterRAM/1GB,2) } else { 0 }',
    'Write-Output ("SAMPLE|" + $cpu + "|" + $ramP + "|" + $diskP + "|" + $gpuR)',
  ];
  runPowerShell(scriptLines, (err, stdout) => {
    const match = stdout.trim().match(/SAMPLE\|([\d.]+)\|([\d.]+)\|([\d.]+)\|([\d.]+)/);
    if (!match) return;
    resourceHistory.samples.push({ ts: Date.now(), cpu: parseFloat(match[1]), ram: parseFloat(match[2]), disk: parseFloat(match[3]), gpu: parseFloat(match[4]) });
    if (resourceHistory.samples.length > resourceHistory.maxSamples) resourceHistory.samples.shift();
  });
}
recogerMuestra();
setInterval(recogerMuestra, 60000);

app.get('/api/sysinfo/historico', (req, res) => {
  const periodo = req.query.periodo || '24h';
  const ahora   = Date.now();
  const ventana = periodo === '7d' ? 7 * 24 * 3600 * 1000 : 24 * 3600 * 1000;
  let muestras  = resourceHistory.samples.filter(s => s.ts >= ahora - ventana);
  if (muestras.length > 200) {
    const step = Math.ceil(muestras.length / 200);
    muestras = muestras.filter((_, i) => i % step === 0);
  }
  res.json({ periodo, total: muestras.length, muestras: muestras.map(s => ({ ts: new Date(s.ts).toISOString(), cpu: s.cpu, ram: s.ram, disk: s.disk, gpu: s.gpu })) });
});

// ─── PROXY ANTHROPIC (evita CORS del navegador) ──────────────
app.post('/api/ai/chat', async (req, res) => {
  try {
    const https = require('https');
    const body  = JSON.stringify(req.body);
    const options = {
      hostname: 'api.anthropic.com',
      port: 443,
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'Content-Length':    Buffer.byteLength(body),
        'anthropic-version': '2023-06-01',
        'x-api-key':         req.headers['x-api-key'] || '',
      }
    };

    const proxyReq = https.request(options, (proxyRes) => {
      res.status(proxyRes.statusCode);
      res.set('Content-Type', 'application/json');
      let data = '';
      proxyRes.on('data', chunk => { data += chunk; });
      proxyRes.on('end', () => { res.send(data); });
    });

    proxyReq.on('error', (e) => {
      console.error('[AI Proxy] Error:', e.message);
      res.status(500).json({ error: { message: 'Error conectando con Anthropic: ' + e.message } });
    });

    proxyReq.setTimeout(30000, () => {
      proxyReq.destroy();
      res.status(504).json({ error: { message: 'Timeout conectando con Anthropic' } });
    });

    proxyReq.write(body);
    proxyReq.end();
  } catch(e) {
    console.error('[AI Proxy] Error:', e.message);
    res.status(500).json({ error: { message: e.message } });
  }
});

// ─── MÓDULO SIEM ──────────────────────────────────────────────
require('./siem.js')(app, getPool, runPowerShell);

// ─── ARRANQUE ─────────────────────────────────────────────────

function startServer() {
  // Redireccion HTTP a HTTPS (puerto 80)
  const httpServer = http.createServer((req, httpRes) => {
    httpRes.writeHead(301, { Location: 'https://' + req.headers.host + req.url });
    httpRes.end();
  });
  httpServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn('[HTTP] Puerto 80 ocupado (IIS activo) — se omite redireccion');
    } else {
      console.error('[HTTP] Error:', err.message);
    }
  });
  httpServer.listen(80, () => console.log('[HTTP] Puerto 80 -> 443'));

  // Servidor principal HTTPS o fallback HTTP
  if (fs.existsSync(SSL_CERT) && fs.existsSync(SSL_KEY)) {
    const sslOptions = { cert: fs.readFileSync(SSL_CERT), key: fs.readFileSync(SSL_KEY) };
    const httpsServer = https.createServer(sslOptions, app);
    httpsServer.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error('[HTTPS] Puerto 443 ocupado. Detén IIS con: iisreset /stop');
        console.warn('[FALLBACK] Arrancando en puerto 8080...');
        const fb = http.createServer(app);
        fb.on('error', (e) => console.error('[8080] Error:', e.message));
        fb.listen(8080, () => console.log('\n[FALLBACK] http://localhost:8080\n'));
      } else {
        console.error('[HTTPS] Error:', err.message);
      }
    });
    httpsServer.listen(443, () => {
      console.log('\n OK Servidor HTTPS en https://localhost:443\n');
    });
  } else {
    console.warn('\n AVISO Certificados SSL no encontrados');
    const httpFb = http.createServer(app);
    httpFb.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error('[ERROR] Puerto 8080 ocupado. Cierra el proceso que lo usa.');
        process.exit(1);
      } else {
        console.error('[8080] Error:', err.message);
      }
    });
    httpFb.listen(8080, () => console.log('\n AVISO Servidor HTTP en http://localhost:8080\n'));
  }
}

startServer();