/**
 * siem_alertas_avanzadas.js
 * Motor de detección avanzada para el SIEM
 * Incluir en siem.js al final del módulo
 */

module.exports = function(getPool, runPowerShell, registrarEvento, ipv4) {

  function ps(lines, cb) { runPowerShell(lines, cb); }

  // Fallback por si ipv4 no se pasa como parametro
  if (typeof ipv4 !== 'function') {
    ipv4 = function(ip) {
      if (!ip) return '';
      ip = String(ip).trim();
      if (ip.toLowerCase().startsWith('::ffff:')) return ip.substring(7);
      if (ip === '::1') return '127.0.0.1';
      return ip;
    };
  }

  // ── IPs ya conocidas por país (caché en memoria) ───────
  const ipGeoCache = {};
  // ── Historial de conexiones para beaconing ─────────────
  const conexionesHist = {}; // ip -> [timestamps]
  // ── Historial tráfico saliente ─────────────────────────
  const traficoHist = [];
  // ── Intentos login web ─────────────────────────────────
  const loginWebHist = {}; // ip -> [timestamps]

  // Dominios C2 conocidos (lista reducida representativa)
  const C2_DOMINIOS = [
    'pastebin.com','ngrok.io','serveo.net','portmap.io',
    'requestbin.net','webhook.site','burpcollaborator.net',
    'dnsbin.zhack.ca','canarytokens.com','interactsh.com',
    '0.0.0.0','raw.githubusercontent.com'
  ];

  // User-Agents sospechosos
  const UA_SOSPECHOSOS = [
    'python-requests','curl/','wget/','go-http-client',
    'masscan','nmap','nikto','sqlmap','hydra','metasploit',
    'msfconsole','dirbuster','gobuster','wfuzz','burpsuite',
    'zgrab','nuclei','httpx','feroxbuster'
  ];

  // Horas consideradas inusuales (fuera de 07:00-21:00)
  function esHorarioInusual() {
    const h = new Date().getHours();
    return h < 7 || h > 21;
  }

  // ═══════════════════════════════════════════════════════
  //  1. LOGIN GEOGRÁFICAMENTE IMPOSIBLE
  //     Umbral: 1 evento / 300s
  //     Lógica: mismo usuario, IPs de países distintos en < 5min
  // ═══════════════════════════════════════════════════════
  async function detectarGeoImposible() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-300)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624;StartTime=$desde} -MaxEvents 100 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml  = [xml]$e.ToXml()',
      '    $data = $xml.Event.EventData.Data',
      '    $user = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '    $ip   = ($data | Where-Object { $_.Name -eq "IpAddress" })."#text"',
      '    $ts   = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")',
      '    if ($ip -and $ip -ne "-" -and $ip -ne "127.0.0.1" -and $ip -ne "::1") {',
      '      Write-Output ("LOGIN|" + $ts + "|" + $user + "|" + $ip)',
      '    }',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const logins = {};
        stdout.split('\n').forEach(line => {
          line = line.trim();
          if (!line.startsWith('LOGIN|')) return;
          const [, ts, user, ip] = line.split('|');
          if (!user || !ip) return;
          if (!logins[user]) logins[user] = [];
          logins[user].push({ ts, ip });
        });

        // Detectar mismo usuario con IPs de /8 distintos en < 5min
        for (const [user, entries] of Object.entries(logins)) {
          if (entries.length < 2) continue;
          const ips = [...new Set(entries.map(e => e.ip))];
          const rangos = ips.map(ip => ip.split('.')[0]);
          const rangosUnicos = [...new Set(rangos)];
          if (rangosUnicos.length >= 2) {
            await registrarEvento({
              tipo: 'geo_imposible',
              severidad: 'high',
              titulo: 'Login geográficamente imposible — Usuario: ' + user,
              detalle: 'El usuario ' + user + ' ha iniciado sesión desde IPs en rangos distintos en menos de 5 minutos: ' + ips.join(', '),
              usuario: user,
              ip_origen: ips[0],
            });
          }
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  2. ACCESO EN HORARIO INUSUAL
  //     Umbral: 1 evento / 60s — Solo fuera de 07:00-21:00
  // ═══════════════════════════════════════════════════════
  async function detectarHorarioInusual() {
    if (!esHorarioInusual()) return;
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624;StartTime=$desde} -MaxEvents 20 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml  = [xml]$e.ToXml()',
      '    $data = $xml.Event.EventData.Data',
      '    $user = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '    $ip   = ($data | Where-Object { $_.Name -eq "IpAddress" })."#text"',
      '    $tipo = ($data | Where-Object { $_.Name -eq "LogonType" })."#text"',
      '    if ($user -and $user -notmatch "\\$") {',
      '      Write-Output ("LOGIN|" + $user + "|" + $ip + "|Tipo:" + $tipo)',
      '    }',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('LOGIN|'));
        if (lineas.length === 0) return resolve();
        const hora = new Date().getHours();
        await registrarEvento({
          tipo: 'horario_inusual',
          severidad: hora >= 0 && hora < 5 ? 'high' : 'medium',
          titulo: 'Acceso detectado en horario inusual (' + hora + ':00h) — ' + lineas.length + ' login(s)',
          detalle: 'Logins fuera del horario habitual (07:00-21:00): ' + lineas.slice(0,5).map(l => l.split('|')[1]).join(', '),
          usuario: lineas[0].split('|')[1] || '',
          ip_origen: lineas[0].split('|')[2] || '',
        });
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  3. CUENTA INACTIVA MÁS DE 30 DÍAS
  //     Umbral: 1 evento / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarCuentaInactiva() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$limite = (Get-Date).AddDays(-30)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624;StartTime=$desde} -MaxEvents 20 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml  = [xml]$e.ToXml()',
      '    $data = $xml.Event.EventData.Data',
      '    $user = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '    if (-not $user -or $user -match "\\$" -or $user -eq "SYSTEM") { continue }',
      '    $adUser = Get-ADUser $user -Properties LastLogonDate -ErrorAction SilentlyContinue',
      '    if ($adUser -and $adUser.LastLogonDate -and $adUser.LastLogonDate -lt $limite) {',
      '      $dias = [int]((Get-Date) - $adUser.LastLogonDate).TotalDays',
      '      Write-Output ("INACTIVA|" + $user + "|" + $dias)',
      '    }',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('INACTIVA|'));
        for (const l of lineas) {
          const [, user, dias] = l.split('|');
          await registrarEvento({
            tipo: 'cuenta_inactiva',
            severidad: parseInt(dias) > 90 ? 'high' : 'medium',
            titulo: 'Cuenta inactiva usada: ' + user + ' (sin acceso hace ' + dias + ' días)',
            detalle: 'La cuenta ' + user + ' llevaba ' + dias + ' días sin actividad y acaba de iniciar sesión.',
            usuario: user,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  4. PASSWORD SPRAYING
  //     Umbral: 5 usuarios distintos fallidos / 60s desde misma IP
  // ═══════════════════════════════════════════════════════
  async function detectarPasswordSpraying() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625;StartTime=$desde} -MaxEvents 500 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml  = [xml]$e.ToXml()',
      '    $data = $xml.Event.EventData.Data',
      '    $user = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '    $ip   = ($data | Where-Object { $_.Name -eq "IpAddress" })."#text"',
      '    if ($ip -and $ip -ne "-") { Write-Output ("FAIL|" + $ip + "|" + $user) }',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        // Agrupar por IP -> usuarios distintos
        const ipUsuarios = {};
        stdout.split('\n').forEach(l => {
          l = l.trim();
          if (!l.startsWith('FAIL|')) return;
          const [, ip, user] = l.split('|');
          if (!ip || !user) return;
          if (!ipUsuarios[ip]) ipUsuarios[ip] = new Set();
          ipUsuarios[ip].add(user);
        });

        for (const [ip, usuarios] of Object.entries(ipUsuarios)) {
          if (usuarios.size >= 5) {
            await registrarEvento({
              tipo: 'password_spraying',
              severidad: usuarios.size >= 10 ? 'critical' : 'high',
              titulo: 'Password Spraying desde ' + ip + ' — ' + usuarios.size + ' usuarios distintos',
              detalle: 'La IP ' + ip + ' intentó autenticar ' + usuarios.size + ' cuentas distintas en 60s: ' + [...usuarios].slice(0,8).join(', '),
              ip_origen: ipv4(ip),
            });
          }
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  5. CREDENCIALES EN TEXTO CLARO
  //     Umbral: 1 evento / 60s — LogonType 8 (NetworkCleartext)
  // ═══════════════════════════════════════════════════════
  async function detectarCredencialesClaras() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624;StartTime=$desde} -MaxEvents 100 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml  = [xml]$e.ToXml()',
      '    $data = $xml.Event.EventData.Data',
      '    $tipo = ($data | Where-Object { $_.Name -eq "LogonType" })."#text"',
      '    if ($tipo -eq "8") {',
      '      $user = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '      $ip   = ($data | Where-Object { $_.Name -eq "IpAddress" })."#text"',
      '      Write-Output ("CLEAR|" + $user + "|" + $ip)',
      '    }',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('CLEAR|'));
        for (const l of lineas) {
          const [, user, ip] = l.split('|');
          await registrarEvento({
            tipo: 'credencial_clara',
            severidad: 'high',
            titulo: 'Autenticación con credenciales en texto claro — Usuario: ' + user,
            detalle: 'LogonType 8 (NetworkCleartext) detectado. El usuario ' + user + ' se autenticó enviando credenciales sin cifrar desde ' + ip,
            usuario: user,
            ip_origen: ipv4(ip),
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  6. RESET DE CONTRASEÑA SIN SOLICITUD
  //     Umbral: 1 / 300s — EventID 4723 y 4724
  // ═══════════════════════════════════════════════════════
  async function detectarResetSinSolicitud() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-300)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4723,4724;StartTime=$desde} -MaxEvents 50 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml  = [xml]$e.ToXml()',
      '    $data = $xml.Event.EventData.Data',
      '    $target  = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '    $subject = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"',
      '    $eid  = $e.Id',
      '    Write-Output ("RESET|" + $eid + "|" + $subject + "|" + $target)',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('RESET|'));
        for (const l of lineas) {
          const [, eid, subject, target] = l.split('|');
          const tipo = eid === '4724' ? 'Reset forzado por administrador' : 'Cambio de contraseña';
          await registrarEvento({
            tipo: 'reset_sin_solicitud',
            severidad: eid === '4724' ? 'high' : 'medium',
            titulo: tipo + ' — ' + subject + ' → ' + target,
            detalle: 'EventID ' + eid + ': ' + subject + ' cambió la contraseña de ' + target + '. Verificar si fue autorizado.',
            usuario: target,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  7. CAMBIO MASIVO DE CONTRASEÑAS AD
  //     Umbral: 3 resets / 300s
  // ═══════════════════════════════════════════════════════
  async function detectarCambioMasivoPass() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-300)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4723,4724;StartTime=$desde} -MaxEvents 200 -ErrorAction SilentlyContinue',
      'if ($evs) { Write-Output ("COUNT|" + $evs.Count) } else { Write-Output "COUNT|0" }',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        const match = stdout.match(/COUNT\|(\d+)/);
        const count = match ? parseInt(match[1]) : 0;
        if (count >= 3) {
          await registrarEvento({
            tipo: 'cambio_masivo_pass',
            severidad: count >= 10 ? 'critical' : 'high',
            titulo: 'Cambio masivo de contraseñas detectado — ' + count + ' resets en 5 minutos',
            detalle: count + ' cambios/resets de contraseña en 300s. Posible ataque de preparación para ransomware o limpieza de huellas.',
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  8. USUARIO CON PRIVILEGIOS CREADO EN AD
  //     Umbral: 1 / 60s — EventID 4728 (añadido a grupo admin)
  // ═══════════════════════════════════════════════════════
  async function detectarUsuarioAdminAD() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      // 4728 = miembro añadido a grupo de seguridad global (Admins)
      // 4732 = miembro añadido a grupo de seguridad local
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4728,4732,4756;StartTime=$desde} -MaxEvents 20 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml   = [xml]$e.ToXml()',
      '    $data  = $xml.Event.EventData.Data',
      '    $member= ($data | Where-Object { $_.Name -eq "MemberName" })."#text"',
      '    $group = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '    $actor = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"',
      '    if ($group -match "Admin|Domain Admin|Enterprise Admin|Schema Admin") {',
      '      Write-Output ("ADMIN|" + $member + "|" + $group + "|" + $actor)',
      '    }',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('ADMIN|'));
        for (const l of lineas) {
          const [, member, group, actor] = l.split('|');
          await registrarEvento({
            tipo: 'usuario_admin_ad',
            severidad: 'critical',
            titulo: 'Usuario añadido a grupo privilegiado: ' + group,
            detalle: actor + ' añadió a ' + member + ' al grupo "' + group + '". Verificar si fue autorizado.',
            usuario: member,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  9. PASS THE HASH
  //     Umbral: 1 / 60s — LogonType 3 con NTLM y sin Kerberos
  // ═══════════════════════════════════════════════════════
  async function detectarPassTheHash() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624;StartTime=$desde} -MaxEvents 200 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml   = [xml]$e.ToXml()',
      '    $data  = $xml.Event.EventData.Data',
      '    $logonType  = ($data | Where-Object { $_.Name -eq "LogonType" })."#text"',
      '    $authPkg    = ($data | Where-Object { $_.Name -eq "AuthenticationPackageName" })."#text"',
      '    $logonProc  = ($data | Where-Object { $_.Name -eq "LogonProcessName" })."#text"',
      '    $user  = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '    $ip    = ($data | Where-Object { $_.Name -eq "IpAddress" })."#text"',
      // PtH: LogonType=3, NTLM, NtLmSsp, sin Kerberos
      '    if ($logonType -eq "3" -and $authPkg -eq "NTLM" -and $logonProc -eq "NtLmSsp" -and $user -notmatch "\\$") {',
      '      Write-Output ("PTH|" + $user + "|" + $ip)',
      '    }',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('PTH|'));
        for (const l of lineas.slice(0, 3)) {
          const [, user, ip] = l.split('|');
          await registrarEvento({
            tipo: 'pass_the_hash',
            severidad: 'critical',
            titulo: 'Pass-the-Hash detectado — Usuario: ' + user + ' desde ' + ip,
            detalle: 'Autenticación NTLM tipo 3 (red) sin Kerberos. Indicador clásico de Pass-the-Hash. Usuario: ' + user + ', IP: ' + ip,
            usuario: user,
            ip_origen: ipv4(ip),
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  10. ANOMALÍAS KERBEROS
  //      Umbral: 2 / 60s — EventIDs 4768,4769,4771
  // ═══════════════════════════════════════════════════════
  async function detectarKerberosAnomalia() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      // 4771 = Kerberos pre-auth fallido, 4768 código de error, 4769 ticket inusual
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4771,4768,4769;StartTime=$desde} -MaxEvents 100 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      '$fallos = ($evs | Where-Object { $_.Id -eq 4771 }).Count',
      '$tickets= ($evs | Where-Object { $_.Id -eq 4769 -and $_.Message -match "0x1" }).Count',
      'Write-Output ("KERB|" + $fallos + "|" + $tickets)',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const match = stdout.match(/KERB\|(\d+)\|(\d+)/);
        if (!match) return resolve();
        const [, fallos, tickets] = match;
        if (parseInt(fallos) >= 2 || parseInt(tickets) >= 2) {
          await registrarEvento({
            tipo: 'kerberos_anomalia',
            severidad: parseInt(fallos) >= 5 ? 'critical' : 'high',
            titulo: 'Anomalía Kerberos — ' + fallos + ' fallos preauth, ' + tickets + ' tickets inusuales',
            detalle: 'Posible AS-REP Roasting o Kerberoasting. Fallos preauth (4771): ' + fallos + ', Tickets con encriptado débil (4769): ' + tickets,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  11. DCSYNC ATTACK
  //      Umbral: 1 / 60s — EventID 4662 con GUID de replicación
  // ═══════════════════════════════════════════════════════
  async function detectarDCSync() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4662;StartTime=$desde} -MaxEvents 50 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  $msg = $e.Message',
      // GUIDs de Replicating Directory Changes
      '  if ($msg -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $msg -match "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") {',
      '    $xml  = [xml]$e.ToXml()',
      '    $data = $xml.Event.EventData.Data',
      '    $subj = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"',
      '    Write-Output ("DCSYNC|" + $subj)',
      '  }',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('DCSYNC|'));
        for (const l of lineas.slice(0, 2)) {
          const user = l.split('|')[1] || '—';
          await registrarEvento({
            tipo: 'dcsync',
            severidad: 'critical',
            titulo: 'DCSync Attack detectado — ' + user + ' solicitó replicación de directorio',
            detalle: 'EventID 4662 con GUIDs de "Replicating Directory Changes". Indica extracción de hashes NTLM mediante DCSync (mimikatz /dcsync). Usuario: ' + user,
            usuario: user,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  12. ESCANEO DE PUERTOS
  //      Umbral: 15 conexiones a puertos distintos en 10s
  // ═══════════════════════════════════════════════════════
  async function detectarPortScan() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$conns = Get-NetTCPConnection -State Listen,SynReceived -ErrorAction SilentlyContinue',
      '$grupos = $conns | Group-Object -Property RemoteAddress | Where-Object { $_.Count -ge 15 -and $_.Name -ne "0.0.0.0" -and $_.Name -ne "::" }',
      'foreach ($g in $grupos) {',
      '  $puertos = ($g.Group | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique) -join ","',
      '  Write-Output ("SCAN|" + $g.Name + "|" + $g.Count + "|" + $puertos)',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('SCAN|'));
        for (const l of lineas) {
          const [, ip, count, puertos] = l.split('|');
          await registrarEvento({
            tipo: 'port_scan',
            severidad: parseInt(count) >= 50 ? 'critical' : 'high',
            titulo: 'Escaneo de puertos detectado desde ' + ip + ' — ' + count + ' puertos',
            detalle: 'La IP ' + ip + ' está escaneando ' + count + ' puertos. Puertos detectados: ' + (puertos||'').substring(0,200),
            ip_origen: ipv4(ip),
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  13. PICO DE TRÁFICO SALIENTE
  //      Umbral: Conexiones salientes > 100 únicas en 60s
  // ═══════════════════════════════════════════════════════
  async function detectarTraficoSaliente() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |',
      '  Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }',
      '$count = ($conns | Select-Object -ExpandProperty RemoteAddress | Sort-Object -Unique).Count',
      'Write-Output ("TRAFICO|" + $count)',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        const match = stdout.match(/TRAFICO\|(\d+)/);
        const count = match ? parseInt(match[1]) : 0;
        traficoHist.push({ count, ts: Date.now() });
        if (traficoHist.length > 10) traficoHist.shift();
        const max = Math.max(...traficoHist.map(e => e.count));
        const avg = traficoHist.reduce((a, e) => a + e.count, 0) / traficoHist.length;
        if (count > 100 && count > avg * 3 && traficoHist.length >= 3) {
          await registrarEvento({
            tipo: 'trafico_saliente',
            severidad: count > 500 ? 'critical' : 'high',
            titulo: 'Pico de tráfico saliente — ' + count + ' conexiones únicas activas',
            detalle: 'Conexiones salientes establecidas: ' + count + ' (media histórica: ' + Math.round(avg) + '). Posible exfiltración de datos.',
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  14. CONEXIÓN A DOMINIO C2
  //      Umbral: 1 / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarConexionC2() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue',
      '$output = New-Object System.Collections.ArrayList',
      'foreach ($c in $conns) {',
      '  try {',
      '    $host = [System.Net.Dns]::GetHostEntry($c.RemoteAddress).HostName',
      '    Write-Output ("CONN|" + $c.RemoteAddress + "|" + $host + "|" + $c.RemotePort)',
      '  } catch {',
      '    Write-Output ("CONN|" + $c.RemoteAddress + "||" + $c.RemotePort)',
      '  }',
      '} | Select-Object -First 50',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('CONN|'));
        for (const l of lineas) {
          const [, ip, host, port] = l.split('|');
          const esC2 = C2_DOMINIOS.some(d => (host||'').includes(d));
          if (esC2) {
            await registrarEvento({
              tipo: 'conexion_c2',
              severidad: 'critical',
              titulo: 'Conexión a dominio C2 conocido: ' + (host||ip),
              detalle: 'Conexión activa a ' + ip + ':' + port + ' (' + (host||'sin DNS') + '). Este dominio está en la lista de infraestructura C2 conocida.',
              ip_origen: ipv4(ip),
            });
          }
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  15. BEACONING
  //      Umbral: 5 conexiones regulares a misma IP en 300s
  //      Detecta intervalos regulares (±10%) = C2 beacon
  // ═══════════════════════════════════════════════════════
  async function detectarBeaconing() {
    const ahora = Date.now();
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |',
      '  Where-Object { $_.RemoteAddress -notmatch "^(127|10|192\\.168|172\\.(1[6-9]|2[0-9]|3[01]))" }',
      'foreach ($c in $conns) { Write-Output ("IP|" + $c.RemoteAddress) }',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        stdout.split('\n').forEach(l => {
          const match = l.trim().match(/^IP\|(.+)/);
          if (!match) return;
          const ip = match[1].trim();
          if (!conexionesHist[ip]) conexionesHist[ip] = [];
          conexionesHist[ip].push(ahora);
          // Limpiar más de 10 minutos
          conexionesHist[ip] = conexionesHist[ip].filter(t => (ahora - t) < 600000);
        });

        // Analizar regularidad
        for (const [ip, timestamps] of Object.entries(conexionesHist)) {
          if (timestamps.length < 5) continue;
          const sorted = [...timestamps].sort();
          const intervals = [];
          for (let i = 1; i < sorted.length; i++) intervals.push(sorted[i] - sorted[i-1]);
          const avg = intervals.reduce((a,b) => a+b, 0) / intervals.length;
          const variance = intervals.map(i => Math.abs(i - avg) / avg);
          const regularidad = variance.filter(v => v < 0.1).length;
          if (regularidad >= 4 && avg > 5000 && avg < 120000) {
            await registrarEvento({
              tipo: 'beaconing',
              severidad: 'high',
              titulo: 'Beaconing detectado hacia ' + ip,
              detalle: 'La IP ' + ip + ' recibe conexiones cada ~' + Math.round(avg/1000) + 's con regularidad > 80%. Indica posible C2 beacon activo.',
              ip_origen: ipv4(ip),
            });
            conexionesHist[ip] = []; // Reset para no repetir
          }
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  16. ENUMERACIÓN SMB
  //      Umbral: 3 / 30s — EventID 5140/5145
  // ═══════════════════════════════════════════════════════
  async function detectarSMBEnum() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-30)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=5140,5145;StartTime=$desde} -MaxEvents 100 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      '$grupos = $evs | Group-Object { ',
      '  $xml = [xml]$_.ToXml()',
      '  ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"',
      '} | Where-Object { $_.Count -ge 3 }',
      'foreach ($g in $grupos) { Write-Output ("SMB|" + $g.Name + "|" + $g.Count) }',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('SMB|'));
        for (const l of lineas) {
          const [, ip, count] = l.split('|');
          await registrarEvento({
            tipo: 'smb_enum',
            severidad: parseInt(count) >= 10 ? 'critical' : 'high',
            titulo: 'Enumeración SMB desde ' + ip + ' — ' + count + ' accesos en 30s',
            detalle: 'La IP ' + ip + ' está accediendo a múltiples recursos compartidos SMB. Posible enumeración de red o movimiento lateral.',
            ip_origen: ipv4(ip),
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  17. STICKY KEYS / ACCESSIBILITY BACKDOOR
  //      Umbral: 1 / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarStickyKeys() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$paths = @(',
      '  "C:\\Windows\\System32\\sethc.exe",',
      '  "C:\\Windows\\System32\\utilman.exe",',
      '  "C:\\Windows\\System32\\osk.exe",',
      '  "C:\\Windows\\System32\\magnify.exe"',
      ')',
      'foreach ($p in $paths) {',
      '  if (Test-Path $p) {',
      '    $hash = (Get-FileHash $p -Algorithm MD5 -ErrorAction SilentlyContinue).Hash',
      '    $size = (Get-Item $p).Length',
      '    Write-Output ("FILE|" + $p + "|" + $hash + "|" + $size)',
      '  }',
      '}',
    ];

    // Hashes MD5 conocidos de binarios legítimos de Windows
    const HASHES_LEGITIMOS = {
      'sethc.exe':   null, // Se aprende en primera ejecución
      'utilman.exe': null,
    };

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        stdout.split('\n').forEach(async l => {
          l = l.trim();
          if (!l.startsWith('FILE|')) return;
          const [, path, hash, size] = l.split('|');
          const nombre = path.split('\\').pop();
          // Si el tamaño es inusualmente grande puede indicar sustitución por cmd.exe
          if (parseInt(size) > 1000000) {
            await registrarEvento({
              tipo: 'sticky_keys',
              severidad: 'critical',
              titulo: 'Posible backdoor Sticky Keys: ' + nombre + ' tiene tamaño inusual (' + Math.round(parseInt(size)/1024) + ' KB)',
              detalle: path + ' tiene un tamaño inusual que sugiere sustitución por cmd.exe u otro ejecutable. Hash: ' + hash,
            });
          }
        });
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  18. ABUSO DE TAREAS PROGRAMADAS
  //      Umbral: 1 / 60s — EventID 4698 (tarea creada)
  // ═══════════════════════════════════════════════════════
  async function detectarTareasProgramadas() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4698,4702;StartTime=$desde} -MaxEvents 20 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  try {',
      '    $xml   = [xml]$e.ToXml()',
      '    $data  = $xml.Event.EventData.Data',
      '    $tarea = ($data | Where-Object { $_.Name -eq "TaskName" })."#text"',
      '    $actor = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"',
      '    $contenido = ($data | Where-Object { $_.Name -eq "TaskContent" })."#text"',
      '    Write-Output ("TASK|" + $e.Id + "|" + $actor + "|" + $tarea)',
      '  } catch {}',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('TASK|'));
        for (const l of lineas) {
          const [, eid, actor, tarea] = l.split('|');
          await registrarEvento({
            tipo: 'tarea_programada',
            severidad: 'high',
            titulo: (eid === '4698' ? 'Nueva tarea programada' : 'Tarea programada modificada') + ': ' + tarea,
            detalle: 'EventID ' + eid + ': ' + actor + ' creó/modificó la tarea "' + tarea + '". Las tareas son un vector común de persistencia.',
            usuario: actor,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  19. DLL HIJACKING / MODIFICACIÓN DLL SEARCH ORDER
  //      Umbral: 1 / 60s — DLLs escritas en directorios no estándar
  // ═══════════════════════════════════════════════════════
  async function detectarDLLHijack() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$limite = (Get-Date).AddSeconds(-60)',
      '$rutas = @("C:\\Users","C:\\Temp","C:\\Windows\\Temp","C:\\ProgramData")',
      'foreach ($ruta in $rutas) {',
      '  if (-not (Test-Path $ruta)) { continue }',
      '  $dlls = Get-ChildItem $ruta -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue |',
      '    Where-Object { $_.LastWriteTime -ge $limite }',
      '  foreach ($d in $dlls) {',
      '    Write-Output ("DLL|" + $d.FullName + "|" + $d.LastWriteTime)',
      '  }',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('DLL|'));
        for (const l of lineas.slice(0, 3)) {
          const [, path, ts] = l.split('|');
          await registrarEvento({
            tipo: 'dll_hijack',
            severidad: 'high',
            titulo: 'DLL escrita en directorio no estándar: ' + path.split('\\').pop(),
            detalle: 'Nueva DLL detectada en ruta inusual (posible DLL hijacking): ' + path + ' — Modificada: ' + ts,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  20. DESACTIVACIÓN DE HERRAMIENTAS DE SEGURIDAD
  //      Umbral: 1 / 60s — EventID 7036 (servicio detenido)
  // ═══════════════════════════════════════════════════════
  async function detectarSeguridadDesactivada() {
    const SERVICIOS_SEGURIDAD = ['WinDefend','MsMpSvc','wscsvc','Sense','WdNisSvc','SecurityHealthService','eventlog','audiosrv'];
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="System";Id=7036;StartTime=$desde} -MaxEvents 50 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  if ($e.Message -match "detenido|stopped") {',
      '    Write-Output ("SVC|" + $e.Message)',
      '  }',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('SVC|'));
        for (const l of lineas) {
          const msg = l.substring(4);
          const esSeguridad = SERVICIOS_SEGURIDAD.some(s => msg.toLowerCase().includes(s.toLowerCase()));
          if (esSeguridad) {
            await registrarEvento({
              tipo: 'seguridad_desactivada',
              severidad: 'critical',
              titulo: 'Herramienta de seguridad detenida: ' + msg.substring(0, 80),
              detalle: msg.substring(0, 300),
            });
          }
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  21. BORRADO DE LOGS
  //      Umbral: 1 / 60s — EventID 1102 y 104
  // ═══════════════════════════════════════════════════════
  async function detectarLogsBorrados() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      '$evs1 = Get-WinEvent -FilterHashtable @{LogName="Security";Id=1102;StartTime=$desde} -MaxEvents 5 -ErrorAction SilentlyContinue',
      '$evs2 = Get-WinEvent -FilterHashtable @{LogName="System";Id=104;StartTime=$desde} -MaxEvents 5 -ErrorAction SilentlyContinue',
      '$total = @($evs1) + @($evs2) | Where-Object { $_ }',
      'foreach ($e in $total) {',
      '  $xml  = [xml]$e.ToXml()',
      '  $data = $xml.Event.EventData.Data',
      '  $user = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"',
      '  Write-Output ("BORRADO|" + $e.Id + "|" + $user)',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('BORRADO|'));
        for (const l of lineas) {
          const [, eid, user] = l.split('|');
          await registrarEvento({
            tipo: 'logs_borrados',
            severidad: 'critical',
            titulo: 'Log de eventos borrado (EventID ' + eid + ') por ' + (user||'desconocido'),
            detalle: 'EventID ' + eid + ': Alguien borró el log de ' + (eid==='1102'?'Seguridad':'Sistema') + '. Usuario: ' + (user||'—') + '. Técnica anti-forense.',
            usuario: user,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  22. DESACTIVACIÓN SHADOW COPIES
  //      Umbral: 1 / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarShadowCopyDelete() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      // EventID 524 en System o 7040 cuando vss se detiene, también buscar en procesos
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="VSS";StartTime=$desde} -MaxEvents 10 -ErrorAction SilentlyContinue',
      'if ($evs) {',
      '  foreach ($e in $evs) { Write-Output ("VSS|" + $e.Id + "|" + $e.Message.Substring(0,[Math]::Min(150,$e.Message.Length))) }',
      '}',
      // También detectar vssadmin en procesos recientes
      '$procs = Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -match "vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled" }',
      'foreach ($p in $procs) { Write-Output ("VSSADMIN|" + $p.CommandLine) }',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('VSS|') || l.startsWith('VSSADMIN|'));
        for (const l of lineas.slice(0, 2)) {
          const esVssAdmin = l.startsWith('VSSADMIN|');
          await registrarEvento({
            tipo: 'shadow_copy_delete',
            severidad: 'critical',
            titulo: esVssAdmin ? 'Comando de borrado de Shadow Copies ejecutado' : 'Actividad VSS sospechosa detectada',
            detalle: l.substring(l.indexOf('|')+1).substring(0,300) + '. Técnica típica de ransomware para impedir recuperación.',
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  23. MODIFICACIÓN ARCHIVO HOSTS
  //      Umbral: 1 / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarHostsModificado() {
    const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$f = Get-Item "' + hostsPath + '" -ErrorAction SilentlyContinue',
      'if ($f) {',
      '  $mod = $f.LastWriteTime',
      '  $hace = (Get-Date) - $mod',
      '  if ($hace.TotalSeconds -le 60) {',
      '    $contenido = Get-Content "' + hostsPath + '" | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }',
      '    Write-Output ("HOSTS|" + $mod.ToString("yyyy-MM-dd HH:mm:ss") + "|" + ($contenido -join " ;; "))',
      '  }',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('HOSTS|'));
        for (const l of lineas) {
          const [, ts, contenido] = l.split('|');
          await registrarEvento({
            tipo: 'hosts_modificado',
            severidad: 'high',
            titulo: 'Archivo hosts modificado — ' + ts,
            detalle: 'El archivo hosts fue modificado hace menos de 60 segundos. Contenido actual: ' + (contenido||'').substring(0,300),
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  24. CAMBIOS EN GPO
  //      Umbral: 1 / 300s — EventID 5136, 5137
  // ═══════════════════════════════════════════════════════
  async function detectarGPOCambio() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-300)',
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=5136,5137,5141;StartTime=$desde} -MaxEvents 10 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      'foreach ($e in $evs) {',
      '  $xml  = [xml]$e.ToXml()',
      '  $data = $xml.Event.EventData.Data',
      '  $obj  = ($data | Where-Object { $_.Name -eq "ObjectDN" })."#text"',
      '  $subj = ($data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"',
      '  if ($obj -match "GroupPolicyContainer") {',
      '    Write-Output ("GPO|" + $e.Id + "|" + $subj + "|" + $obj)',
      '  }',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('GPO|'));
        for (const l of lineas.slice(0,2)) {
          const [, eid, subj, obj] = l.split('|');
          await registrarEvento({
            tipo: 'gpo_cambio',
            severidad: 'high',
            titulo: 'Cambio en política de grupo (GPO) por ' + subj,
            detalle: 'EventID ' + eid + ': ' + subj + ' modificó la GPO: ' + (obj||'').substring(0,150),
            usuario: subj,
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  25. TÚNEL DNS
  //      Umbral: 10 peticiones DNS inusualmente largas / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarDNSTunnel() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-60)',
      // EventID 3008 en Microsoft-Windows-DNS-Client o 256 en DNS Server
      '$evs = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-DNS-Client/Operational";StartTime=$desde} -MaxEvents 200 -ErrorAction SilentlyContinue',
      'if (-not $evs) { Write-Output "NONE"; exit }',
      '$largos = $evs | Where-Object { $_.Message.Length -gt 100 } | Measure-Object',
      'Write-Output ("DNS|" + $largos.Count)',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim() || stdout.includes('NONE')) return resolve();
        const match = stdout.match(/DNS\|(\d+)/);
        const count = match ? parseInt(match[1]) : 0;
        if (count >= 10) {
          await registrarEvento({
            tipo: 'dns_tunnel',
            severidad: count >= 50 ? 'critical' : 'high',
            titulo: 'Posible túnel DNS — ' + count + ' peticiones con nombres inusualmente largos',
            detalle: count + ' peticiones DNS con subdominios/nombres largos detectadas en 60s. Los túneles DNS codifican datos en los nombres de dominio para exfiltrar información.',
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  26. TRANSFERENCIA MASIVA ICMP
  //      Umbral: 50 paquetes ICMP > 64 bytes / 10s
  // ═══════════════════════════════════════════════════════
  async function detectarICMPMasivo() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$stats = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Select-Object -First 1',
      // Usar contador de rendimiento para ICMP
      '$icmpOut = (Get-Counter "\\ICMP\\Messages Sent/sec" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue',
      'if ($icmpOut -and $icmpOut -gt 50) { Write-Output ("ICMP|" + [int]$icmpOut) } else { Write-Output "ICMP|0" }',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        const match = stdout.match(/ICMP\|(\d+)/);
        const count = match ? parseInt(match[1]) : 0;
        if (count >= 50) {
          await registrarEvento({
            tipo: 'icmp_masivo',
            severidad: count >= 200 ? 'critical' : 'high',
            titulo: 'Transferencia masiva ICMP — ' + count + ' mensajes/seg',
            detalle: count + ' mensajes ICMP por segundo detectados. Puede indicar exfiltración de datos via ICMP tunnel o DDoS.',
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  27. USER-AGENT SOSPECHOSO (en logs IIS/web)
  //      Umbral: 1 / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarUserAgentSospechoso() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$logPaths = @(',
      '  "C:\\inetpub\\logs\\LogFiles\\W3SVC1",',
      '  "C:\\Windows\\System32\\LogFiles\\HTTPERR"',
      ')',
      'foreach ($logPath in $logPaths) {',
      '  if (-not (Test-Path $logPath)) { continue }',
      '  $logFile = Get-ChildItem $logPath -Filter "*.log" | Sort-Object LastWriteTime | Select-Object -Last 1',
      '  if (-not $logFile) { continue }',
      '  $lineas = Get-Content $logFile.FullName -Tail 100 -ErrorAction SilentlyContinue',
      '  foreach ($l in $lineas) {',
      '    Write-Output ("LOG|" + $l)',
      '  }',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('LOG|'));
        for (const l of lineas) {
          const contenido = l.substring(4).toLowerCase();
          const ua = UA_SOSPECHOSOS.find(s => contenido.includes(s));
          if (ua) {
            await registrarEvento({
              tipo: 'useragent_sospechoso',
              severidad: ['sqlmap','metasploit','nikto','msfconsole'].includes(ua) ? 'critical' : 'high',
              titulo: 'User-Agent sospechoso detectado: ' + ua,
              detalle: 'Se detectó una petición web con User-Agent de herramienta de hacking: "' + ua + '". Línea de log: ' + l.substring(4,200),
            });
            break; // Solo 1 evento por ciclo
          }
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  28. CONEXIÓN DIRECTA A IP SIN RESOLUCIÓN DNS
  //      Umbral: 3 / 60s — Conexiones a IPs sin hostname
  // ═══════════════════════════════════════════════════════
  async function detectarConexionSinDNS() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |',
      '  Where-Object { $_.RemoteAddress -notmatch "^(127|10|192\\.168|172\\.(1[6-9]|2[0-9]|3[01])|::1)" }',
      '$sinDNS = 0',
      '$ejemplos = @()',
      'foreach ($c in ($conns | Select-Object -First 20)) {',
      '  try {',
      '    $h = [System.Net.Dns]::GetHostEntry($c.RemoteAddress)',
      '  } catch {',
      '    $sinDNS++',
      '    $ejemplos += $c.RemoteAddress + ":" + $c.RemotePort',
      '  }',
      '}',
      'if ($sinDNS -ge 3) { Write-Output ("NODNS|" + $sinDNS + "|" + ($ejemplos -join ",")) }',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const match = stdout.match(/NODNS\|(\d+)\|(.+)/);
        if (match) {
          const [, count, ejemplos] = match;
          await registrarEvento({
            tipo: 'conexion_sin_dns',
            severidad: parseInt(count) >= 10 ? 'high' : 'medium',
            titulo: 'Conexiones directas a IPs sin resolución DNS — ' + count + ' conexiones',
            detalle: count + ' conexiones activas a IPs sin nombre de dominio resolvible. Puede indicar C2 o herramientas que evitan resolución DNS: ' + ejemplos.substring(0,200),
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  29. MODIFICACIÓN ARCHIVOS CRÍTICOS (.DLL en System32)
  //      Umbral: 1 / 60s
  // ═══════════════════════════════════════════════════════
  async function detectarArchivoCritico() {
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$limite = (Get-Date).AddSeconds(-60)',
      '$rutas = @(',
      '  "C:\\Windows\\System32",',
      '  "C:\\Windows\\SysWOW64",',
      '  "C:\\Windows\\System32\\drivers"',
      ')',
      'foreach ($ruta in $rutas) {',
      '  $archivos = Get-ChildItem $ruta -Filter "*.dll" -ErrorAction SilentlyContinue |',
      '    Where-Object { $_.LastWriteTime -ge $limite } | Select-Object -First 5',
      '  foreach ($a in $archivos) {',
      '    Write-Output ("DLL|" + $a.FullName + "|" + $a.LastWriteTime)',
      '  }',
      '  $exes = Get-ChildItem $ruta -Filter "*.exe" -ErrorAction SilentlyContinue |',
      '    Where-Object { $_.LastWriteTime -ge $limite } | Select-Object -First 3',
      '  foreach ($e in $exes) {',
      '    Write-Output ("EXE|" + $e.FullName + "|" + $e.LastWriteTime)',
      '  }',
      '}',
    ];

    await new Promise(resolve => {
      ps(scriptLines, async (err, stdout) => {
        if (!stdout.trim()) return resolve();
        const lineas = stdout.split('\n').filter(l => l.startsWith('DLL|') || l.startsWith('EXE|'));
        for (const l of lineas.slice(0,3)) {
          const tipo = l.startsWith('DLL|') ? 'DLL' : 'EXE';
          const [, path, ts] = l.split('|');
          await registrarEvento({
            tipo: 'archivo_critico',
            severidad: 'critical',
            titulo: tipo + ' crítico modificado: ' + path.split('\\').pop(),
            detalle: 'Archivo del sistema modificado en los últimos 60s: ' + path + ' — Fecha: ' + ts + '. Posible ataque de sustitución de DLL o inyección.',
          });
        }
        resolve();
      });
    });
  }

  // ═══════════════════════════════════════════════════════
  //  30. BRUTE FORCE EN PANEL WEB (login de la app)
  //      Umbral: 10 intentos / 60s desde misma IP
  //      Registrado en log_accesos de MySQL
  // ═══════════════════════════════════════════════════════
  async function detectarBruteForceWeb() {
    try {
      const db = await getPool();
      const [rows] = await db.execute(`
        SELECT ip, COUNT(*) as intentos
        FROM log_accesos
        WHERE accion = 'login_fail'
        AND fecha >= DATE_SUB(NOW(), INTERVAL 60 SECOND)
        GROUP BY ip
        HAVING intentos >= 10
      `);
      for (const r of rows) {
        await registrarEvento({
          tipo: 'login_fallido',
          severidad: r.intentos >= 30 ? 'critical' : 'high',
          titulo: 'Brute Force en panel web — ' + r.intentos + ' intentos desde ' + r.ip,
          detalle: 'La IP ' + r.ip + ' ha realizado ' + r.intentos + ' intentos de login fallidos en el panel web en los últimos 60 segundos.',
          ip_origen: r.ip,
        });
      }
    } catch(e) {}
  }

  // ═══════════════════════════════════════════════════════
  //  EXPORTAR FUNCIÓN DE EVALUACIÓN
  // ═══════════════════════════════════════════════════════
  // Mapa tipo -> función de detección
  const mapaDetecciones = {
    'geo_imposible':          detectarGeoImposible,
    'horario_inusual':        detectarHorarioInusual,
    'cuenta_inactiva':        detectarCuentaInactiva,
    'password_spraying':      detectarPasswordSpraying,
    'credencial_clara':       detectarCredencialesClaras,
    'reset_sin_solicitud':    detectarResetSinSolicitud,
    'cambio_masivo_pass':     detectarCambioMasivoPass,
    'usuario_admin_ad':       detectarUsuarioAdminAD,
    'pass_the_hash':          detectarPassTheHash,
    'kerberos_anomalia':      detectarKerberosAnomalia,
    'dcsync':                 detectarDCSync,
    'port_scan':              detectarPortScan,
    'trafico_saliente':       detectarTraficoSaliente,
    'conexion_c2':            detectarConexionC2,
    'beaconing':              detectarBeaconing,
    'smb_enum':               detectarSMBEnum,
    'sticky_keys':            detectarStickyKeys,
    'tarea_programada':       detectarTareasProgramadas,
    'dll_hijack':             detectarDLLHijack,
    'seguridad_desactivada':  detectarSeguridadDesactivada,
    'logs_borrados':          detectarLogsBorrados,
    'shadow_copy_delete':     detectarShadowCopyDelete,
    'hosts_modificado':       detectarHostsModificado,
    'gpo_cambio':             detectarGPOCambio,
    'dns_tunnel':             detectarDNSTunnel,
    'icmp_masivo':            detectarICMPMasivo,
    'useragent_sospechoso':   detectarUserAgentSospechoso,
    'conexion_sin_dns':       detectarConexionSinDNS,
    'archivo_critico':        detectarArchivoCritico,
    'login_fallido':          detectarBruteForceWeb,
  };

  return async function evaluarAlertasAvanzadas() {
    // Cargar estado de alertas desde BD en cada ciclo
    // desactivadas = tipos que existen en BD y están desactivados o con acción ninguna
    // NO ejecutar si está en desactivadas
    // SÍ ejecutar si está activa en BD o si no existe en BD (detección siempre activa)
    let desactivadas = new Set();
    try {
      const db = await getPool();
      const [rows] = await db.execute(
        'SELECT tipo, activa, accion FROM siem_alertas'
      );
      // Marcar como desactivadas las que están en BD con activa=0 o accion=ninguna
      rows.forEach(r => {
        if (!r.activa || r.accion === 'ninguna') {
          desactivadas.add(r.tipo);
        }
      });
    } catch(e) {
      // Si falla BD ejecutar todas (fail-open)
      desactivadas = new Set();
    }

    for (const [tipo, fn] of Object.entries(mapaDetecciones)) {
      // Saltar SOLO si el tipo está explícitamente desactivado en BD
      if (desactivadas.has(tipo)) {
        continue;
      }
      try { await fn(); } catch(e) { /* silencioso */ }
    }
  };
};