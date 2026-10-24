/**
 * siem.js — Módulo SIEM completo
 * require('./siem.js')(app, getPool, runPowerShell)
 */

const os   = require('os');
const fs   = require('fs');
const path = require('path');

module.exports = function(app, getPool, runPowerShell) {

  function ps(lines, cb) { runPowerShell(lines, cb); }

  // ── Helper IPv6 → IPv4 ────────────────────────────────
  function ipv4(ip) {
    if (!ip) return '';
    ip = String(ip).trim();
    if (ip.toLowerCase().startsWith('::ffff:')) return ip.substring(7);
    if (ip === '::1') return '127.0.0.1';
    const m = ip.match(/^(?:0+:){5}(?:0+|ffff):([\d.]+)$/i);
    if (m) return m[1];
    return ip;
  }

  function normalizarIP(ip) {
    return ipv4((ip || '').trim());
  }

  // ── Cache de exclusiones en memoria (se recarga cada 60s) ──
  let exclusionesCache = [];
  let exclusionesCacheTs = 0;

  async function getExclusiones() {
    const ahora = Date.now();
    if (ahora - exclusionesCacheTs < 60000) return exclusionesCache;
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT * FROM siem_exclusiones WHERE activa=1');
      exclusionesCache  = rows;
      exclusionesCacheTs = ahora;
    } catch(e) {}
    return exclusionesCache;
  }

  // ── Comprobar si un evento está excluido ──────────────
  async function estaExcluido(ev, alertaId) {
    const excls = await getExclusiones();
    return excls.some(ex => {
      // Si la exclusión es para una alerta concreta, verificar que coincide
      if (ex.alerta_id && ex.alerta_id !== alertaId) return false;
      const val = (ex.valor || '').toLowerCase();
      if (ex.tipo === 'ip'       && ev.ip_origen && normalizarIP(ev.ip_origen).toLowerCase() === val) return true;
      if (ex.tipo === 'usuario'  && ev.usuario   && ev.usuario.toLowerCase()  === val) return true;
      if (ex.tipo === 'proceso'  && ev.proceso   && ev.proceso.toLowerCase().includes(val)) return true;
      if (ex.tipo === 'dominio'  && ev.ip_origen && ev.ip_origen.toLowerCase().includes(val)) return true;
      return false;
    });
  }

  // ── ENDPOINTS EXCLUSIONES ─────────────────────────────

  app.get('/api/siem/exclusiones', async (req, res) => {
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT e.*, a.nombre as alerta_nombre FROM siem_exclusiones e LEFT JOIN siem_alertas a ON e.alerta_id=a.id ORDER BY e.creada_en DESC');
      res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/exclusiones', async (req, res) => {
    const { tipo, valor, descripcion, alerta_id } = req.body;
    if (!tipo || !valor) return res.status(400).json({ error: 'Tipo y valor requeridos' });
    try {
      const db = await getPool();
      await db.execute(
        'INSERT INTO siem_exclusiones (tipo, valor, descripcion, alerta_id) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE activa=1, descripcion=?',
        [tipo, valor.trim(), descripcion||'', alerta_id||null, descripcion||'']
      );
      exclusionesCacheTs = 0; // Invalidar caché
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/siem/exclusiones/desde_evento/:id — excluir desde un evento existente
  app.post('/api/siem/exclusiones/desde_evento/:id', async (req, res) => {
    const { excluir } = req.body; // ['ip', 'usuario', 'proceso']
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT * FROM siem_eventos WHERE id=?', [parseInt(req.params.id)]);
      if (!rows.length) return res.status(404).json({ error: 'Evento no encontrado' });
      const ev = rows[0];
      const creadas = [];
      for (const campo of (excluir || [])) {
        let valor = null;
        if (campo === 'ip'      && ev.ip_origen) valor = normalizarIP(ev.ip_origen);
        if (campo === 'usuario' && ev.usuario)   valor = ev.usuario;
        if (campo === 'proceso' && ev.proceso)   valor = ev.proceso;
        if (!valor) continue;
        await db.execute(
          'INSERT IGNORE INTO siem_exclusiones (tipo, valor, descripcion, alerta_id) VALUES (?,?,?,NULL)',
          [campo, valor, 'Auto-excluido desde evento #' + ev.id]
        );
        creadas.push(campo + ':' + valor);
      }
      exclusionesCacheTs = 0;
      res.json({ ok: true, creadas });
    } catch(err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/api/siem/exclusiones/:id', async (req, res) => {
    try {
      const db = await getPool();
      await db.execute('UPDATE siem_exclusiones SET activa=0 WHERE id=?', [parseInt(req.params.id)]);
      exclusionesCacheTs = 0;
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.put('/api/siem/exclusiones/:id', async (req, res) => {
    const { activa, descripcion } = req.body;
    try {
      const db = await getPool();
      await db.execute('UPDATE siem_exclusiones SET activa=?, descripcion=? WHERE id=?', [activa?1:0, descripcion||'', parseInt(req.params.id)]);
      exclusionesCacheTs = 0;
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // Endpoint para excluir directamente desde un evento
  app.post('/api/siem/excluir_evento/:id', async (req, res) => {
    const { excluir_ip, excluir_usuario, excluir_proceso, descripcion } = req.body;
    try {
      const db = await getPool();
      const [[ev]] = await db.execute('SELECT * FROM siem_eventos WHERE id=?', [parseInt(req.params.id)]);
      if (!ev) return res.status(404).json({ error: 'Evento no encontrado' });
      const insertadas = [];
      if (excluir_ip && ev.ip_origen && ev.ip_origen !== '—') {
        await db.execute('INSERT IGNORE INTO siem_exclusiones (tipo,valor,descripcion) VALUES (?,?,?)', ['ip', normalizarIP(ev.ip_origen), descripcion||'Excluido desde evento #'+ev.id]);
        insertadas.push('IP: ' + ev.ip_origen);
      }
      if (excluir_usuario && ev.usuario) {
        await db.execute('INSERT IGNORE INTO siem_exclusiones (tipo,valor,descripcion) VALUES (?,?,?)', ['usuario', ev.usuario, descripcion||'Excluido desde evento #'+ev.id]);
        insertadas.push('Usuario: ' + ev.usuario);
      }
      if (excluir_proceso && ev.proceso) {
        await db.execute('INSERT IGNORE INTO siem_exclusiones (tipo,valor,descripcion) VALUES (?,?,?)', ['proceso', ev.proceso, descripcion||'Excluido desde evento #'+ev.id]);
        insertadas.push('Proceso: ' + ev.proceso);
      }
      exclusionesCacheTs = 0;
      res.json({ ok: true, insertadas });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ── Registrar evento en BD ────────────────────────────
  async function registrarEvento(ev) {
    try {
      // Comprobar exclusiones antes de registrar
      const excluido = await estaExcluido(ev, ev.alerta_id || null);
      if (excluido) {
        console.log('[SIEM] Evento excluido por whitelist: ' + ev.titulo);
        return;
      }
      const db = await getPool();
      await db.execute(
        'INSERT INTO siem_eventos (tipo, severidad, titulo, detalle, ip_origen, usuario, proceso) VALUES (?,?,?,?,?,?,?)',
        [
          ev.tipo      || 'desconocido',
          ev.severidad || 'medium',
          ev.titulo    || '',
          ev.detalle   || '',
          normalizarIP(ev.ip_origen || ''),
          ev.usuario   || '',
          ev.proceso   || '',
        ]
      );
      console.log('[SIEM] ' + (ev.severidad||'').toUpperCase() + ' — ' + ev.titulo);
    } catch(e) {
      console.error('[SIEM] Error registrando evento:', e.message);
    }
  }

  // ══════════════════════════════════════════════════════
  //  EVENTOS
  // ══════════════════════════════════════════════════════

  app.get('/api/siem/eventos', async (req, res) => {
    const limite    = Math.min(parseInt(req.query.limit) || 100, 1000);
    const severidad = req.query.severidad || null;
    const tipo      = req.query.tipo      || null;
    const remediado = req.query.remediado !== undefined ? req.query.remediado : null;
    const archivado = req.query.archivado !== undefined ? req.query.archivado : '0';
    const fp        = req.query.falso_positivo !== undefined ? req.query.falso_positivo : null;
    const busqueda  = req.query.q || null;
    try {
      const db = await getPool();
      let sql = 'SELECT * FROM siem_eventos WHERE 1=1';
      const p = [];
      if (severidad) { sql += ' AND severidad=?'; p.push(severidad); }
      if (tipo)      { sql += ' AND tipo=?';      p.push(tipo); }
      if (remediado !== null && remediado !== '') { sql += ' AND remediado=?'; p.push(parseInt(remediado)); }
      if (archivado !== null && archivado !== '') { sql += ' AND archivado=?'; p.push(parseInt(archivado)); }
      if (fp !== null && fp !== '')               { sql += ' AND falso_positivo=?'; p.push(parseInt(fp)); }
      if (busqueda) {
        sql += ' AND (titulo LIKE ? OR detalle LIKE ? OR ip_origen LIKE ? OR usuario LIKE ? OR atribuido_a LIKE ?)';
        const b = '%' + busqueda + '%';
        p.push(b, b, b, b, b);
      }
      sql += ' ORDER BY fecha DESC LIMIT ' + limite;
      const [rows] = await db.execute(sql, p);
      rows.forEach(r => {
        if (r.ip_origen)  r.ip_origen  = ipv4(r.ip_origen);
        if (r.atribuido_a && /[:]/.test(r.atribuido_a)) r.atribuido_a = ipv4(r.atribuido_a);
      });
      res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/eventos', async (req, res) => {
    const { tipo, severidad, titulo, detalle, ip_origen, usuario, proceso } = req.body;
    try {
      const db = await getPool();
      await db.execute(
        'INSERT INTO siem_eventos (tipo,severidad,titulo,detalle,ip_origen,usuario,proceso) VALUES (?,?,?,?,?,?,?)',
        [tipo, severidad||'medium', titulo, detalle||'', normalizarIP(ip_origen||''), usuario||'', proceso||'']
      );
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/remediar/:id', async (req, res) => {
    const { accion, proceso } = req.body;
    const ip = normalizarIP(req.body.ip || '');
    const id = parseInt(req.params.id);
    let resultado = '';
    try {
      if (accion === 'bloquear_ip' && ip) {
        const rule = 'SIEM_BLOCK_' + ip.replace(/\./g, '_');
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          'netsh advfirewall firewall add rule name="' + rule + '" dir=in action=block remoteip=' + ip,
          'Write-Output "OK"',
        ], (err, out) => { resultado = 'IP ' + ip + ' bloqueada en Firewall'; resolve(); }));
      } else if (accion === 'matar_proceso' && proceso) {
        const safe = proceso.replace(/[^a-zA-Z0-9.\-]/g, '');
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          'Stop-Process -Name "' + safe + '" -Force -ErrorAction SilentlyContinue',
          'Write-Output "OK"',
        ], (err, out) => { resultado = 'Proceso ' + safe + ' terminado'; resolve(); }));
      } else if (accion === 'aislar_sistema') {
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound',
          'netsh advfirewall firewall add rule name="SIEM_ALLOW_LOCAL" dir=in action=allow remoteip=127.0.0.1',
          'netsh advfirewall firewall add rule name="SIEM_ALLOW_LOCAL_OUT" dir=out action=allow remoteip=127.0.0.1',
          'Write-Output "OK"',
        ], (err, out) => { resultado = 'Sistema aislado - solo tráfico local'; resolve(); }));
      } else {
        resultado = 'Marcado como remediado manualmente';
      }
      if (id > 0) {
        const db = await getPool();
        await db.execute(
          'UPDATE siem_eventos SET remediado=1, remediacion=? WHERE id=?',
          [resultado, id]
        );
      }
      res.json({ ok: true, resultado });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/falso_positivo/:id', async (req, res) => {
    try {
      const db = await getPool();
      await db.execute(
        'UPDATE siem_eventos SET falso_positivo=1, archivado=1, remediado=1, remediacion="Marcado como falso positivo" WHERE id=?',
        [parseInt(req.params.id)]
      );
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/archivar/:id', async (req, res) => {
    try {
      const db = await getPool();
      await db.execute('UPDATE siem_eventos SET archivado=1 WHERE id=?', [parseInt(req.params.id)]);
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/siem/tipos', async (req, res) => {
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT DISTINCT tipo FROM siem_eventos ORDER BY tipo');
      res.json(rows.map(r => r.tipo));
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════════════
  //  ALERTAS
  // ══════════════════════════════════════════════════════

  app.get('/api/siem/alertas', async (req, res) => {
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT * FROM siem_alertas ORDER BY id');
      // Asegurar tipos numéricos correctos
      rows.forEach(r => {
        r.threshold   = parseInt(r.threshold)   || 1;
        r.ventana_seg = parseInt(r.ventana_seg) || 60;
        r.activa      = r.activa ? 1 : 0;
      });
      res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/alertas/:id', async (req, res) => {
    const id          = parseInt(req.params.id);
    const threshold   = parseInt(req.body.threshold)   || 1;
    const ventana_seg = parseInt(req.body.ventana_seg) || 60;
    const activa      = req.body.activa ? 1 : 0;
    const accion      = req.body.accion  || 'notificar';
    const nombre      = req.body.nombre  || '';
    try {
      const db = await getPool();
      const [result] = await db.execute(
        'UPDATE siem_alertas SET threshold=?, ventana_seg=?, activa=?, accion=?, nombre=? WHERE id=?',
        [threshold, ventana_seg, activa, accion, nombre, id]
      );
      // Limpiar cooldown para que el cambio tenga efecto inmediato
      delete alertasDisparadas['alerta_' + id];
      console.log('[SIEM] Alerta '+id+' actualizada: threshold='+threshold+' ventana='+ventana_seg+'s activa='+activa+' accion='+accion);
      res.json({ ok: true, threshold, ventana_seg, activa, accion });
    } catch(e) {
      console.error('[SIEM] Error actualizando alerta:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // ══════════════════════════════════════════════════════
  //  CONFIGURACIÓN
  // ══════════════════════════════════════════════════════

  app.get('/api/siem/config', async (req, res) => {
    const defaults = { vt_api_key: '', alerta_email: '', modo_activo: '1', bloqueo_automatico: '0' };
    try {
      const db = await getPool();
      for (const [clave, valor] of Object.entries(defaults)) {
        await db.execute(
          'INSERT IGNORE INTO siem_config (clave, valor, descripcion) VALUES (?, ?, ?)',
          [clave, valor, clave]
        );
      }
      const [rows] = await db.execute('SELECT * FROM siem_config');
      const cfg = { ...defaults };
      rows.forEach(r => { cfg[r.clave] = r.valor || ''; });
      res.json(cfg);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/config', async (req, res) => {
    try {
      const db = await getPool();
      for (const [clave, valor] of Object.entries(req.body)) {
        await db.execute(
          'INSERT INTO siem_config (clave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor=?',
          [clave, valor, valor]
        );
      }
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════════════
  //  STATS + GRÁFICO CIRCULAR
  // ══════════════════════════════════════════════════════

  app.get('/api/siem/stats', async (req, res) => {
    try {
      const db = await getPool();
      const [[total]]     = await db.execute("SELECT COUNT(*) as n FROM siem_eventos WHERE archivado=0 AND falso_positivo=0");
      const [[criticos]]  = await db.execute("SELECT COUNT(*) as n FROM siem_eventos WHERE severidad='critical' AND remediado=0 AND archivado=0 AND falso_positivo=0");
      const [[altos]]     = await db.execute("SELECT COUNT(*) as n FROM siem_eventos WHERE severidad='high' AND remediado=0 AND archivado=0 AND falso_positivo=0");
      const [[medios]]    = await db.execute("SELECT COUNT(*) as n FROM siem_eventos WHERE severidad='medium' AND remediado=0 AND archivado=0 AND falso_positivo=0");
      const [[bajos]]     = await db.execute("SELECT COUNT(*) as n FROM siem_eventos WHERE severidad='low' AND remediado=0 AND archivado=0 AND falso_positivo=0");
      const [[pendientes]]= await db.execute("SELECT COUNT(*) as n FROM siem_eventos WHERE remediado=0 AND archivado=0 AND falso_positivo=0");
      const [[malware]]   = await db.execute("SELECT COUNT(*) as n FROM siem_virustotal WHERE veredicto='malware'");
      const [[fps]]       = await db.execute("SELECT COUNT(*) as n FROM siem_eventos WHERE falso_positivo=1");
      const [recientes]   = await db.execute("SELECT tipo, COUNT(*) as n FROM siem_eventos WHERE fecha >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND archivado=0 GROUP BY tipo ORDER BY n DESC LIMIT 10");
      // Período anterior (24h-48h) para calcular tendencia
      const [anteriores]  = await db.execute("SELECT tipo, COUNT(*) as n FROM siem_eventos WHERE fecha BETWEEN DATE_SUB(NOW(), INTERVAL 48 HOUR) AND DATE_SUB(NOW(), INTERVAL 24 HOUR) AND archivado=0 GROUP BY tipo");
      const mapAnterior = {};
      anteriores.forEach(r => { mapAnterior[r.tipo] = r.n; });
      recientes.forEach(r => {
        const prev = mapAnterior[r.tipo] || 0;
        const diff = r.n - prev;
        r.anterior = prev;
        r.diff     = diff;
        r.tendencia_pct = prev > 0 ? Math.round((diff / prev) * 100) : (r.n > 0 ? 100 : 0);
      });
      const totalSev = criticos.n + altos.n + medios.n + bajos.n;
      const pct = (n) => totalSev ? Math.round((n / totalSev) * 100) : 0;
      res.json({
        total: total.n, criticos: criticos.n, altos: altos.n, medios: medios.n, bajos: bajos.n,
        pendientes: pendientes.n, malware: malware.n, falsos_positivos: fps.n, recientes,
        grafico: {
          critical: criticos.n, high: altos.n, medium: medios.n, low: bajos.n,
          pct_critical: pct(criticos.n), pct_high: pct(altos.n),
          pct_medium: pct(medios.n), pct_low: pct(bajos.n),
        },
      });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════════════
  //  LOGINS AD / WINDOWS
  // ══════════════════════════════════════════════════════

  app.get('/api/siem/logins', (req, res) => {
    const lineas = Math.min(parseInt(req.query.lineas) || 200, 1000);
    const tipo   = req.query.tipo || 'todos';

    // Script PowerShell con doble método: Get-WinEvent (preferido) + Get-EventLog (fallback)
    // Switch en líneas separadas para compatibilidad con Windows Server 2016
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$output = New-Object System.Collections.ArrayList',
      '$desde  = (Get-Date).AddHours(-24)',

      // Intentar Get-WinEvent primero (más detallado)
      '$evs = $null',
      'try {',
      '  $evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624,4625,4647,4648,4771,4776,4740;StartTime=$desde} -MaxEvents ' + lineas + ' -ErrorAction Stop',
      '} catch {}',

      // Si Get-WinEvent funcionó, parsear con XML
      'if ($evs -and $evs.Count -gt 0) {',
      '  foreach ($e in $evs) {',
      '    try {',
      '      $xml    = [xml]$e.ToXml()',
      '      $data   = $xml.Event.EventData.Data',
      '      $eid    = [int]$e.Id',
      '      $ts     = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")',
      '      $user   = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"',
      '      $ip     = ($data | Where-Object { $_.Name -eq "IpAddress" })."#text"',
      '      $domain = ($data | Where-Object { $_.Name -eq "TargetDomainName" })."#text"',
      '      $logonT = ($data | Where-Object { $_.Name -eq "LogonType" })."#text"',
      '      $auth   = ($data | Where-Object { $_.Name -eq "AuthenticationPackageName" })."#text"',
      '      $wkst   = ($data | Where-Object { $_.Name -eq "WorkstationName" })."#text"',
      '      if ($ip -match "^::ffff:") { $ip = $ip.Substring(7) }',
      '      if ($ip -eq "::1") { $ip = "127.0.0.1" }',
      '      if (-not $ip) { $ip = "-" }',
      '      if (-not $user) { $user = "-" }',
      // Switch en líneas separadas — compatible con PS 2.0+
      '      $tipoStr = "OTRO"',
      '      if ($eid -eq 4624) { $tipoStr = "EXITOSO" }',
      '      elseif ($eid -eq 4625) { $tipoStr = "FALLIDO" }',
      '      elseif ($eid -eq 4647) { $tipoStr = "LOGOFF" }',
      '      elseif ($eid -eq 4648) { $tipoStr = "EXPLICITO" }',
      '      elseif ($eid -eq 4771) { $tipoStr = "KERBEROS_FAIL" }',
      '      elseif ($eid -eq 4776) { $tipoStr = "NTLM_FAIL" }',
      '      elseif ($eid -eq 4740) { $tipoStr = "BLOQUEADO" }',
      '      if ($user -ne "-" -and $user -notmatch "^\\$") {',
      '        $linea = "[$ts] [$tipoStr] [ID:$eid] Usuario:$user Dominio:$domain IP:$ip Workstation:$wkst Auth:$auth LogonType:$logonT"',
      '        [void]$output.Add($linea)',
      '      }',
      '    } catch {}',
      '  }',
      '}',

      // Fallback: Get-EventLog si Get-WinEvent no devolvió nada
      'if ($output.Count -eq 0) {',
      '  $ids2 = @(4624,4625,4647,4648,4740)',
      '  foreach ($eid2 in $ids2) {',
      '    try {',
      '      $evs2 = Get-EventLog -LogName Security -InstanceId $eid2 -After $desde -Newest ' + Math.min(lineas, 100) + ' -ErrorAction SilentlyContinue',
      '      foreach ($e2 in $evs2) {',
      '        $ts2    = $e2.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")',
      '        $msg2   = ($e2.Message -replace "[\\r\\n\\t]+"," ").Substring(0,[Math]::Min(300,$e2.Message.Length))',
      '        $tipoStr2 = "OTRO"',
      '        if ($eid2 -eq 4624) { $tipoStr2 = "EXITOSO" }',
      '        elseif ($eid2 -eq 4625) { $tipoStr2 = "FALLIDO" }',
      '        elseif ($eid2 -eq 4647) { $tipoStr2 = "LOGOFF" }',
      '        elseif ($eid2 -eq 4648) { $tipoStr2 = "EXPLICITO" }',
      '        elseif ($eid2 -eq 4740) { $tipoStr2 = "BLOQUEADO" }',
      '        [void]$output.Add("[$ts2] [$tipoStr2] [ID:$eid2] $msg2")',
      '      }',
      '    } catch {}',
      '  }',
      '}',

      'if ($output.Count -eq 0) {',
      '  [void]$output.Add("[INFO] Sin eventos de login en las ultimas 24h o sin permisos. Ejecuta node server.js como Administrador.")',
      '}',
      '$output',
    ];

    runPowerShell(scriptLines, (err, stdout, stderr) => {
      let lineasArr = stdout
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.startsWith('['))
        .map(raw => ({
          raw: raw
            .replace(/::ffff:([\d.]+)/gi, '$1')
            .replace(/::1\b/g, '127.0.0.1')
        }));

      if (tipo === 'exitosos')   lineasArr = lineasArr.filter(l => /EXITOSO|EXPLICITO/.test(l.raw));
      if (tipo === 'fallidos')   lineasArr = lineasArr.filter(l => /FALLIDO|KERBEROS_FAIL|NTLM_FAIL/.test(l.raw));
      if (tipo === 'bloqueados') lineasArr = lineasArr.filter(l => /BLOQUEADO/.test(l.raw));
      if (tipo === 'kerberos')   lineasArr = lineasArr.filter(l => /KERBEROS/.test(l.raw));

      res.json({
        lineas: lineasArr,
        fuente: 'Windows Security Event Log — 4624/4625/4647/4648/4771/4776/4740',
        total:  lineasArr.length,
      });
    });
  });

  // ══════════════════════════════════════════════════════
  //  SOFTWARE / PROCESOS / VIRUSTOTAL / HASH
  // ══════════════════════════════════════════════════════

  app.get('/api/siem/software', (req, res) => {
    const dias = parseInt(req.query.dias) || 7;
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$output = New-Object System.Collections.ArrayList',
      '$fecha  = (Get-Date).AddDays(-' + dias + ')',
      '$regPaths = @("HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*","HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*")',
      '$apps = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.InstallDate }',
      'foreach ($a in $apps) {',
      '  try {',
      '    $ts = [datetime]::ParseExact($a.InstallDate,"yyyyMMdd",$null)',
      '    if ($ts -ge $fecha) { [void]$output.Add("[" + $ts.ToString("yyyy-MM-dd") + "] [SOFTWARE] " + $a.DisplayName + " v" + $a.DisplayVersion + " | " + $a.Publisher) }',
      '  } catch {}',
      '}',
      '$evs = Get-EventLog -LogName Application -Source "MsiInstaller" -InstanceId 11707 -After $fecha -ErrorAction SilentlyContinue | Select-Object -First 50',
      'foreach ($e in $evs) {',
      '  $ts  = $e.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")',
      '  $msg = ($e.Message -replace "[\\r\\n]+"," ").Substring(0,[Math]::Min(200,$e.Message.Length))',
      '  [void]$output.Add("[$ts] [MSI_INSTALL] $msg")',
      '}',
      'if ($output.Count -eq 0) { [void]$output.Add("[INFO] Sin software instalado en los últimos ' + dias + ' días") }',
      '$output',
    ];
    ps(scriptLines, (err, stdout) => {
      const lineasArr = stdout.split('\n').map(l => l.trim()).filter(l => l.length > 5).map(raw => ({ raw }));
      res.json({ lineas: lineasArr, fuente: 'Registro de Windows + MsiInstaller' });
    });
  });

  app.get('/api/siem/procesos', (req, res) => {
    const SOSPECHOSOS = ['mimikatz','meterpreter','netcat','nc.exe','psexec','wce','procdump','lazagne','pwdump','cobaltstrike','beacon','empire','metasploit','hydra','medusa','hashcat'];
    const scriptLines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$output = New-Object System.Collections.ArrayList',
      '$sospechosos = @("' + SOSPECHOSOS.join('","') + '")',
      '$procs = Get-Process -ErrorAction SilentlyContinue',
      '$ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")',
      'foreach ($p in $procs) {',
      '  $nombre = $p.Name.ToLower()',
      '  $esSosp = $false',
      '  foreach ($s in $sospechosos) { if ($nombre -like ("*" + $s + "*")) { $esSosp = $true; break } }',
      '  $cpu  = [math]::Round($p.CPU, 1)',
      '  $mem  = [math]::Round($p.WorkingSet64 / 1MB, 1)',
      '  $ruta = ""; try { $ruta = $p.MainModule.FileName } catch {}',
      '  $sev  = if ($esSosp) { "CRITICAL" } elseif ($cpu -gt 80) { "HIGH" } else { "INFO" }',
      '  if ($esSosp -or $cpu -gt 80 -or $mem -gt 500) {',
      '    [void]$output.Add("[$ts] [$sev] PID:" + $p.Id + " | " + $p.Name + " | CPU:" + $cpu + "% | MEM:" + $mem + "MB | " + $ruta)',
      '  }',
      '}',
      'if ($output.Count -eq 0) { [void]$output.Add("[$ts] [OK] Sin procesos sospechosos") }',
      '$output',
    ];
    ps(scriptLines, (err, stdout) => {
      const lineasArr = stdout.split('\n').map(l => l.trim()).filter(l => l.startsWith('[')).map(raw => ({ raw }));
      res.json({ lineas: lineasArr, fuente: 'Get-Process' });
    });
  });

  // ── Helper VT: petición HTTPS directa a VirusTotal ──────
  function vtRequest(path, vtKey, timeoutMs) {
    return new Promise((resolve, reject) => {
      const https = require('https');
      const req = https.request({
        hostname: 'www.virustotal.com',
        port: 443,
        path: path,
        method: 'GET',
        headers: {
          'x-apikey':   vtKey,
          'Accept':     'application/json',
          'User-Agent': 'SysLog-SIEM/1.0',
        },
        rejectUnauthorized: false,
        secureProtocol: 'TLSv1_2_method',
      }, (res) => {
        let data = '';
        res.on('data', d => { data += d; });
        res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
      });
      req.on('error', e => {
        console.error('[VT] Error de red:', e.message, e.code);
        reject(e);
      });
      req.setTimeout(timeoutMs || 20000, () => {
        req.destroy();
        reject(new Error('Timeout (20s) conectando con VirusTotal'));
      });
      req.end();
    });
  }

  // ── Test de conectividad a VT ─────────────────────────────
  app.get('/api/siem/virustotal/test', async (req, res) => {
    const resultado = { pasos: [] };
    // Paso 1: conectividad básica
    try {
      const r = await vtRequest('/', 'test', 10000);
      resultado.pasos.push({ paso: 'Conexión TCP+TLS a virustotal.com', ok: true, status: r.statusCode });
    } catch(e) {
      resultado.pasos.push({ paso: 'Conexión TCP+TLS a virustotal.com', ok: false, error: e.message, code: e.code });
      return res.json({ ok: false, ...resultado });
    }
    // Paso 2: API key
    let vtKey = '';
    try {
      const db = await getPool();
      const [rows] = await db.execute("SELECT valor FROM siem_config WHERE clave='vt_api_key'");
      vtKey = rows.length > 0 ? (rows[0].valor || '').trim() : '';
      resultado.pasos.push({ paso: 'API Key en BD', ok: !!vtKey, valor: vtKey ? vtKey.substring(0,8)+'...' : 'NO CONFIGURADA' });
    } catch(e) {
      resultado.pasos.push({ paso: 'Leer API Key de BD', ok: false, error: e.message });
    }
    if (!vtKey) return res.json({ ok: false, ...resultado });
    // Paso 3: petición real con hash de prueba (EICAR)
    try {
      const r = await vtRequest(
        '/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        vtKey, 15000
      );
      const body = r.body.substring(0, 300);
      resultado.pasos.push({ paso: 'Petición API VT con hash EICAR', ok: r.statusCode === 200, status: r.statusCode, body });
      return res.json({ ok: r.statusCode === 200, ...resultado });
    } catch(e) {
      resultado.pasos.push({ paso: 'Petición API VT', ok: false, error: e.message, code: e.code });
      return res.json({ ok: false, ...resultado });
    }
  });

  app.post('/api/siem/virustotal', async (req, res) => {
    const { hash, apikey } = req.body;
    if (!hash) return res.status(400).json({ error: 'Hash requerido' });
    if (!/^[a-fA-F0-9]{64}$/.test(hash))
      return res.status(400).json({ error: 'Hash SHA256 inválido (debe tener 64 caracteres hexadecimales)' });

    // Obtener API key
    let vtKey = (apikey || '').trim();
    try {
      const db = await getPool();
      if (vtKey) {
        // Guardar la key proporcionada en BD para futuros usos
        await db.execute(
          'INSERT INTO siem_config (clave, valor) VALUES (?,?) ON DUPLICATE KEY UPDATE valor=?',
          ['vt_api_key', vtKey, vtKey]
        );
      } else {
        const [rows] = await db.execute("SELECT valor FROM siem_config WHERE clave='vt_api_key'");
        if (rows.length > 0) vtKey = (rows[0].valor || '').trim();
      }
    } catch(e) { console.error('[VT] Error BD key:', e.message); }
    if (!vtKey) return res.status(400).json({ error: 'API Key de VirusTotal no configurada. Añádela en Ajustes SIEM.' });

    // Comprobar caché
    try {
      const db = await getPool();
      const [cached] = await db.execute('SELECT * FROM siem_virustotal WHERE hash=?', [hash]);
      if (cached.length > 0) {
        const row = cached[0];
        console.log('[VT] Resultado desde caché para hash:', hash.substring(0,16));
        return res.json({
          cached: true, hash: row.hash, nombre: row.nombre,
          positivos: row.positivos, total: row.total, veredicto: row.veredicto,
          resultado: JSON.parse(row.resultado || '{}'),
        });
      }
    } catch(e) {}

    // Llamar a VirusTotal
    console.log('[VT] Consultando VirusTotal para hash:', hash.substring(0,16) + '...');
    try {
      const r = await vtRequest('/api/v3/files/' + hash, vtKey, 20000);

      if (r.statusCode === 404) return res.status(404).json({ error: 'Hash no encontrado en VirusTotal — puede que el archivo no haya sido analizado aún' });
      if (r.statusCode === 401) return res.status(401).json({ error: 'API Key de VirusTotal inválida o sin permisos' });
      if (r.statusCode === 429) return res.status(429).json({ error: 'Límite de peticiones alcanzado (500/día en plan gratuito). Espera 24h o upgrade a plan de pago.' });
      if (r.statusCode !== 200) return res.status(r.statusCode).json({ error: 'Error VirusTotal HTTP ' + r.statusCode + ': ' + r.body.substring(0, 200) });

      const data      = JSON.parse(r.body);
      const attrs     = data.data?.attributes || {};
      const stats     = attrs.last_analysis_stats || {};
      const positivos = (stats.malicious || 0) + (stats.suspicious || 0);
      const total     = Object.values(stats).reduce((a, b) => a + b, 0);
      const veredicto = positivos === 0 ? 'limpio' : positivos < 3 ? 'sospechoso' : 'malware';
      const nombre    = attrs.meaningful_name || attrs.name || hash.substring(0, 16) + '...';
      const tipo_arch = attrs.type_description || attrs.magic || '';
      const tamano    = attrs.size || 0;

      console.log('[VT] Resultado:', veredicto, positivos + '/' + total, nombre);

      // Guardar en caché
      try {
        const db = await getPool();
        await db.execute(
          'INSERT IGNORE INTO siem_virustotal (hash,nombre,resultado,positivos,total,veredicto) VALUES (?,?,?,?,?,?)',
          [hash, nombre, JSON.stringify(data), positivos, total, veredicto]
        );
        if (veredicto !== 'limpio') {
          await registrarEvento({
            tipo: 'malware', severidad: veredicto === 'malware' ? 'critical' : 'high',
            titulo: 'Archivo sospechoso: ' + nombre,
            detalle: 'Hash: ' + hash + ' | Positivos: ' + positivos + '/' + total + ' | Tipo: ' + tipo_arch,
          });
        }
      } catch(e) { console.error('[VT] Error guardando en BD:', e.message); }

      res.json({ cached: false, hash, nombre, positivos, total, veredicto,
        tipo_arch, tamano, stats, motores: attrs.last_analysis_results || {},
        fecha: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      });
    } catch(e) {
      console.error('[VT] Error completo:', e.message, e.code);
      const msg = e.message + (e.code ? ' [' + e.code + ']' : '');
      const sug = (e.code === 'ENOTFOUND' || e.code === 'ECONNREFUSED')
        ? 'El servidor no resuelve virustotal.com. Comprueba DNS o prueba: nslookup www.virustotal.com'
        : e.code === 'ETIMEDOUT' || e.message.includes('Timeout')
        ? 'Timeout al conectar. Comprueba firewall de salida en el puerto 443.'
        : e.code === 'ECONNRESET'
        ? 'La conexión fue resetada. Posible problema de TLS con el servidor.'
        : null;
      res.status(500).json({ error: msg, sugerencia: sug });
    }
  });

  app.post('/api/siem/hash', (req, res) => {
    const { filepath } = req.body;
    if (!filepath) return res.status(400).json({ error: 'Ruta requerida' });
    // Sanitizar ruta
    const safe = filepath.trim().replace(/[;&|`$]/g, '');
    if (!safe) return res.status(400).json({ error: 'Ruta inválida' });
    // Calcular SHA256 con Node.js crypto (más fiable que PowerShell)
    const fs2    = require('fs');
    const crypto = require('crypto');
    if (!fs2.existsSync(safe)) {
      return res.status(404).json({ error: 'Archivo no encontrado: ' + safe });
    }
    try {
      const hash256 = crypto.createHash('sha256');
      const stream  = fs2.createReadStream(safe);
      stream.on('data', d => hash256.update(d));
      stream.on('end', () => {
        const hash = hash256.digest('hex').toUpperCase();
        res.json({ hash, filepath: safe });
      });
      stream.on('error', e => {
        res.status(500).json({ error: 'Error leyendo archivo: ' + e.message });
      });
    } catch(e) {
      res.status(500).json({ error: 'Error calculando hash: ' + e.message });
    }
  });

  // Subir archivo desde el navegador y analizarlo en VT
  app.post('/api/siem/virustotal/upload', async (req, res) => {
    let vtKey = '';
    try {
      const db = await getPool();
      const [rows] = await db.execute("SELECT valor FROM siem_config WHERE clave='vt_api_key'");
      vtKey = rows.length > 0 ? (rows[0].valor || '').trim() : '';
    } catch(e) {}
    if (!vtKey) return res.status(400).json({ error: 'API Key de VirusTotal no configurada.' });

    // Recoger el archivo como buffer desde el body raw
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const buffer = Buffer.concat(chunks);
        // Calcular SHA256 del archivo subido
        const crypto = require('crypto');
        const hash   = crypto.createHash('sha256').update(buffer).digest('hex');
        console.log('[VT Upload] Hash calculado:', hash, 'tamaño:', buffer.length);

        // Comprobar caché primero
        try {
          const db = await getPool();
          const [cached] = await db.execute('SELECT * FROM siem_virustotal WHERE hash=?', [hash]);
          if (cached.length > 0) {
            const row = cached[0];
            return res.json({ cached: true, hash, nombre: row.nombre, positivos: row.positivos, total: row.total, veredicto: row.veredicto });
          }
        } catch(e) {}

        // Analizar hash en VT (si ya existe allí)
        const r = await vtRequest('/api/v3/files/' + hash, vtKey, 20000);
        if (r.statusCode === 200) {
          const data      = JSON.parse(r.body);
          const attrs     = data.data?.attributes || {};
          const stats     = attrs.last_analysis_stats || {};
          const positivos = (stats.malicious || 0) + (stats.suspicious || 0);
          const total     = Object.values(stats).reduce((a, b) => a + b, 0);
          const veredicto = positivos === 0 ? 'limpio' : positivos < 3 ? 'sospechoso' : 'malware';
          const nombre    = attrs.meaningful_name || hash.substring(0, 16) + '...';
          try {
            const db = await getPool();
            await db.execute('INSERT IGNORE INTO siem_virustotal (hash,nombre,resultado,positivos,total,veredicto) VALUES (?,?,?,?,?,?)',
              [hash, nombre, JSON.stringify(data), positivos, total, veredicto]);
          } catch(e) {}
          return res.json({ cached: false, hash, nombre, positivos, total, veredicto, stats, motores: attrs.last_analysis_results || {} });
        }

        // Si no existe en VT (404), subir el archivo
        if (r.statusCode === 404) {
          const https    = require('https');
          const boundary = '----SIEMBoundary' + Date.now();
          const filename = req.headers['x-filename'] || 'archivo.bin';
          const body     = Buffer.concat([
            Buffer.from('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="' + filename + '"\r\nContent-Type: application/octet-stream\r\n\r\n'),
            buffer,
            Buffer.from('\r\n--' + boundary + '--\r\n'),
          ])
          const uploadReq = https.request({
            hostname: 'www.virustotal.com', port: 443,
            path: '/api/v3/files', method: 'POST',
            headers: {
              'x-apikey': vtKey,
              'Content-Type': 'multipart/form-data; boundary=' + boundary,
              'Content-Length': body.length,
            },
            rejectUnauthorized: false, secureProtocol: 'TLSv1_2_method',
          }, uploadRes => {
            let d = '';
            uploadRes.on('data', c => d += c);
            uploadRes.on('end', () => {
              if (uploadRes.statusCode !== 200) return res.status(uploadRes.statusCode).json({ error: 'Error subiendo a VT: HTTP ' + uploadRes.statusCode });
              try {
                const resp = JSON.parse(d);
                res.json({ hash, subido: true, analysis_id: resp.data?.id, mensaje: 'Archivo enviado a VirusTotal para análisis. El resultado estará disponible en unos minutos.' });
              } catch(e) { res.status(500).json({ error: 'Error parseando respuesta de subida' }); }
            });
          });
          uploadReq.on('error', e => res.status(500).json({ error: 'Error subiendo archivo: ' + e.message }));
          uploadReq.write(body);
          uploadReq.end();
        } else {
          res.status(r.statusCode).json({ error: 'Error VT HTTP ' + r.statusCode });
        }
      } catch(e) {
        console.error('[VT Upload] Error:', e.message);
        res.status(500).json({ error: e.message });
      }
    });
    req.on('error', e => res.status(500).json({ error: e.message }));
  });

  // ══════════════════════════════════════════════════════
  //  EXCLUSIONES (WHITELIST)
  // ══════════════════════════════════════════════════════

  // Cache de exclusiones en memoria (se recarga cada 60s)
  async function getExclusiones() {
    const ahora = Date.now();
    if (ahora - exclusionesCacheTs < 60000 && exclusionesCache.length > 0) return exclusionesCache;
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT * FROM siem_exclusiones WHERE activa=1');
      exclusionesCache   = rows;
      exclusionesCacheTs = ahora;
    } catch(e) {}
    return exclusionesCache;
  }

  // Comprobar si un evento está excluido
  async function estaExcluido(ev, alertaId) {
    const excls = await getExclusiones();
    for (const ex of excls) {
      // Aplica a todas las alertas o solo a la alerta especificada
      if (ex.alerta_id !== null && ex.alerta_id !== alertaId) continue;
      const val = ex.valor.toLowerCase();
      switch (ex.tipo) {
        case 'ip':
          if (ev.ip_origen && normalizarIP(ev.ip_origen).toLowerCase() === val) return true;
          if (ev.detalle   && ev.detalle.toLowerCase().includes(val)) return true;
          break;
        case 'usuario':
          if (ev.usuario && ev.usuario.toLowerCase() === val) return true;
          if (ev.detalle && ev.detalle.toLowerCase().includes('usuario:' + val)) return true;
          break;
        case 'proceso':
          if (ev.proceso && ev.proceso.toLowerCase().includes(val)) return true;
          break;
        case 'dominio':
          if (ev.detalle && ev.detalle.toLowerCase().includes(val)) return true;
          break;
        case 'red':
          // Comprobar si la IP está en el rango CIDR (básico para /24)
          if (ev.ip_origen) {
            const ip = normalizarIP(ev.ip_origen);
            const red = ex.valor.replace(/\.\d+\/\d+$/, '');
            if (ip.startsWith(red)) return true;
          }
          break;
      }
    }
    return false;
  }

  // Wrapper de registrarEvento que comprueba exclusiones
  const registrarEventoOriginal = registrarEvento;
  async function registrarEventoConExclusiones(ev, alertaId) {
    if (await estaExcluido(ev, alertaId || null)) {
      console.log('[SIEM] Evento excluido por whitelist: ' + ev.titulo);
      return;
    }
    return registrarEventoOriginal(ev);
  }

  // ══════════════════════════════════════════════════════
  //  KQL PERSONALIZADO
  // ══════════════════════════════════════════════════════

  app.get('/api/siem/kql', async (req, res) => {
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT * FROM siem_alertas_kql ORDER BY creada_en DESC');
      res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/siem/kql', async (req, res) => {
    const { nombre, descripcion, kql_query, threshold, ventana_seg, severidad, activa, accion } = req.body;
    if (!nombre || !kql_query) return res.status(400).json({ error: 'Nombre y query requeridos' });
    try {
      const db = await getPool();
      const [result] = await db.execute(
        'INSERT INTO siem_alertas_kql (nombre,descripcion,kql_query,threshold,ventana_seg,severidad,activa,accion) VALUES (?,?,?,?,?,?,?,?)',
        [nombre, descripcion||'', kql_query, parseInt(threshold)||1, parseInt(ventana_seg)||60, severidad||'medium', activa?1:0, accion||'notificar']
      );
      res.json({ ok: true, id: result.insertId });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.put('/api/siem/kql/:id', async (req, res) => {
    const { nombre, descripcion, kql_query, threshold, ventana_seg, severidad, activa, accion } = req.body;
    try {
      const db = await getPool();
      await db.execute(
        'UPDATE siem_alertas_kql SET nombre=?,descripcion=?,kql_query=?,threshold=?,ventana_seg=?,severidad=?,activa=?,accion=? WHERE id=?',
        [nombre, descripcion||'', kql_query, parseInt(threshold)||1, parseInt(ventana_seg)||60, severidad||'medium', activa?1:0, accion||'notificar', parseInt(req.params.id)]
      );
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  app.delete('/api/siem/kql/:id', async (req, res) => {
    try {
      const db = await getPool();
      await db.execute('DELETE FROM siem_alertas_kql WHERE id=?', [parseInt(req.params.id)]);
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  function kqlToPowerShell(kql, ventana) {
    const lines = [
      '$ErrorActionPreference = "SilentlyContinue"',
      '$desde = (Get-Date).AddSeconds(-' + ventana + ')',
    ];
    if (/SecurityEvent/i.test(kql)) {
      const m = kql.match(/EventID\s*==\s*(\d+)/i);
      const eids = m ? [m[1]] : ['4624', '4625'];
      lines.push('$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=' + eids.join(',') + ';StartTime=$desde} -MaxEvents 500 -ErrorAction SilentlyContinue');
      lines.push('if ($evs) { $evs | ForEach-Object { Write-Output $_.Message.Substring(0,[Math]::Min(150,$_.Message.Length)) } }');
    } else if (/Process/i.test(kql)) {
      lines.push('$procs = Get-Process | Select-Object Name,Id,CPU');
      const nm = kql.match(/ProcessName\s*==\s*["\'](.*?)["\']/ );
      if (nm) lines.push('$procs = $procs | Where-Object { $_.Name -like "*' + nm[1] + '*" }');
      lines.push('$procs | ForEach-Object { Write-Output ($_.Name + " PID:" + $_.Id) }');
    } else if (/Network|Tcp/i.test(kql)) {
      lines.push('Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ($_.RemoteAddress + ":" + $_.RemotePort) }');
    } else {
      lines.push(kql);
    }
    return lines;
  }

  async function ejecutarAlertasKQL() {
    let alertas = [];
    try {
      const db = await getPool();
      const [rows] = await db.execute('SELECT * FROM siem_alertas_kql WHERE activa=1');
      alertas = rows;
    } catch(e) { return; }
    for (const a of alertas) {
      try {
        const script = kqlToPowerShell(a.kql_query, a.ventana_seg);
        await new Promise(resolve => {
          ps(script, async (err, stdout) => {
            if (!stdout.trim()) return resolve();
            const lineas = stdout.split('\n').map(l => l.trim()).filter(Boolean);
            const count  = lineas.filter(l => !l.startsWith('#')).length;
            if (count >= a.threshold) {
              await registrarEvento({
                tipo:      'kql_' + a.nombre.toLowerCase().replace(/\s+/g, '_').substring(0, 30),
                severidad: a.severidad,
                titulo:    '[KQL] ' + a.nombre + ' — ' + count + ' coincidencias',
                detalle:   lineas.slice(0, 10).join('\n'),
              });
              try {
                const db2 = await getPool();
                await db2.execute('UPDATE siem_alertas_kql SET ultima_exec=NOW() WHERE id=?', [a.id]);
              } catch(e) {}
            }
            resolve();
          });
        });
      } catch(e) {}
    }
  }
  setInterval(ejecutarAlertasKQL, 30000);

  // ══════════════════════════════════════════════════════
  //  MOTOR DE ALERTAS BÁSICAS (CPU, RAM, logins, etc.)
  // ══════════════════════════════════════════════════════

  const historial          = { cpu: [], login_fallido: [] };
  const alertasDisparadas  = {};

  async function evaluarAlertas() {
    let alertas = [];
    try {
      const db = await getPool();
      // Recargar desde BD en cada ciclo para respetar cambios en tiempo real
      const [rows] = await db.execute('SELECT * FROM siem_alertas');
      alertas = rows;
    } catch(e) { return; }
    for (const alerta of alertas) {
      // Saltar si desactivada
      if (!alerta.activa || alerta.activa === 0) continue;
      // Saltar si acción es ninguna
      if (alerta.accion === 'ninguna') continue;
      try { await evaluarAlerta(alerta); } catch(e) {}
    }
  }

  async function evaluarAlerta(alerta) {
    // Doble comprobacion de seguridad
    if (!alerta.activa)              return;
    if (alerta.accion === 'ninguna') return;

    // Asegurar que threshold y ventana_seg son números
    alerta.threshold   = parseInt(alerta.threshold)   || 1;
    alerta.ventana_seg = parseInt(alerta.ventana_seg) || 60;

    const ahora     = Date.now();
    const ventanaMs = alerta.ventana_seg * 1000;
    const key       = 'alerta_' + alerta.id;
    if (alertasDisparadas[key] && (ahora - alertasDisparadas[key]) < ventanaMs) return;

    switch (alerta.tipo) {
      case 'cpu_alta': {
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          '$load = (Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average',
          'Write-Output $load',
        ], async (err, stdout) => {
          const cpu = parseFloat(stdout.trim()) || 0;
          historial.cpu.push({ valor: cpu, ts: ahora });
          historial.cpu = historial.cpu.filter(e => (ahora - e.ts) <= ventanaMs);
          const superan = historial.cpu.filter(e => e.valor >= alerta.threshold).length;
          if (superan >= 3) {
            alertasDisparadas[key] = ahora;
            await registrarEventoConExclusiones({ tipo: 'cpu_alta', severidad: cpu >= 95 ? 'critical' : 'high', titulo: 'CPU por encima del ' + alerta.threshold + '% — Actual: ' + cpu.toFixed(1) + '%', detalle: superan + ' muestras superan el threshold de ' + alerta.threshold + '%' });
          }
          resolve();
        }));
        break;
      }
      case 'ram_alta': {
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          '$os  = Get-WmiObject Win32_OperatingSystem',
          '$tot = [long]$os.TotalVisibleMemorySize',
          '$free= [long]$os.FreePhysicalMemory',
          '$pct = [math]::Round((($tot - $free) / $tot) * 100, 1)',
          'Write-Output $pct',
        ], async (err, stdout) => {
          const pct = parseFloat(stdout.trim()) || 0;
          if (pct >= alerta.threshold) {
            alertasDisparadas[key] = ahora;
            await registrarEventoConExclusiones({ tipo: 'ram_alta', severidad: pct >= 95 ? 'critical' : 'high', titulo: 'RAM por encima del ' + alerta.threshold + '% — Actual: ' + pct + '%', detalle: 'Uso de memoria RAM: ' + pct + '%' });
          }
          resolve();
        }));
        break;
      }
      case 'login_fallido': {
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          '$desde = (Get-Date).AddSeconds(-' + alerta.ventana_seg + ')',
          '$evs = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625;StartTime=$desde} -MaxEvents 1000 -ErrorAction SilentlyContinue',
          'if ($evs) { Write-Output $evs.Count } else { Write-Output 0 }',
        ], async (err, stdout) => {
          const count = parseInt(stdout.trim()) || 0;
          if (count >= alerta.threshold) {
            alertasDisparadas[key] = ahora;
            await registrarEventoConExclusiones({ tipo: 'login_fallido', severidad: count >= alerta.threshold * 3 ? 'critical' : 'high', titulo: 'Posible Brute Force — ' + count + ' logins fallidos en ' + alerta.ventana_seg + 's', detalle: count + ' intentos fallidos (threshold: ' + alerta.threshold + ')' });
          }
          resolve();
        }));
        break;
      }
      case 'proceso_sospechoso': {
        const SOSP = ['mimikatz','meterpreter','netcat','nc.exe','psexec','wce','procdump','lazagne','cobaltstrike','beacon','empire','metasploit','hydra','hashcat'];
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          'Get-Process | Select-Object -ExpandProperty Name | ForEach-Object { Write-Output $_.ToLower() }',
        ], async (err, stdout) => {
          const nombres = stdout.split('\n').map(l => l.trim()).filter(Boolean);
          const encontrados = SOSP.filter(s => nombres.some(n => n.includes(s)));
          if (encontrados.length > 0) {
            alertasDisparadas[key] = ahora;
            await registrarEventoConExclusiones({ tipo: 'proceso_sospechoso', severidad: 'critical', titulo: 'Proceso sospechoso: ' + encontrados.join(', '), detalle: 'Procesos detectados: ' + encontrados.join(', '), proceso: encontrados[0] });
          }
          resolve();
        }));
        break;
      }
      case 'software_instalado': {
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          '$desde = (Get-Date).AddSeconds(-' + alerta.ventana_seg + ')',
          '$evs = Get-EventLog -LogName Application -Source "MsiInstaller" -InstanceId 11707 -After $desde -ErrorAction SilentlyContinue | Select-Object -First 5',
          'if ($evs) { foreach ($e in $evs) { $msg = ($e.Message -replace "[\\r\\n]+"," ").Substring(0,[Math]::Min(150,$e.Message.Length)); Write-Output $msg } } else { Write-Output "NONE" }',
        ], async (err, stdout) => {
          const out = stdout.trim();
          if (out && out !== 'NONE') {
            alertasDisparadas[key] = ahora;
            await registrarEventoConExclusiones({ tipo: 'software_instalado', severidad: 'medium', titulo: 'Software instalado recientemente', detalle: out.substring(0, 300) });
          }
          resolve();
        }));
        break;
      }
      case 'disco_alto': {
        await new Promise(resolve => ps([
          '$ErrorActionPreference = "SilentlyContinue"',
          '$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=\'C:\'"',
          '$pct  = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)',
          'Write-Output $pct',
        ], async (err, stdout) => {
          const pct = parseFloat(stdout.trim()) || 0;
          if (pct >= alerta.threshold) {
            alertasDisparadas[key] = ahora;
            await registrarEventoConExclusiones({ tipo: 'disco_alto', severidad: pct >= 95 ? 'critical' : 'high', titulo: 'Disco C: al ' + pct + '% (threshold: ' + alerta.threshold + '%)', detalle: 'Espacio en disco critico: ' + pct + '%' });
          }
          resolve();
        }));
        break;
      }
    }
  }

  // ══════════════════════════════════════════════════════
  //  MOTOR AVANZADO + ARRANQUE
  // ══════════════════════════════════════════════════════

  const evaluarAlertasAvanzadas = require('./siem_alertas_avanzadas.js')(getPool, runPowerShell, registrarEventoConExclusiones, ipv4);

  async function evaluarTodo() {
    await evaluarAlertas();
    await evaluarAlertasAvanzadas();
  }

  setInterval(evaluarTodo, 10000);
  evaluarTodo();

  // Normalizar IPs antiguas en BD cada 30s
  setInterval(async () => {
    try {
      const db = await getPool();
      await db.execute("UPDATE siem_eventos SET ip_origen = SUBSTRING(ip_origen,8) WHERE ip_origen LIKE '::ffff:%'");
      await db.execute("UPDATE siem_eventos SET ip_origen = '127.0.0.1' WHERE ip_origen = '::1'");
    } catch(e) {}
  }, 30000);

  console.log('[SIEM] Modulo cargado — motor de alertas activo (10s basico + avanzado)');
};