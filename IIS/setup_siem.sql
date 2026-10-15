-- ═══════════════════════════════════════════════════════
--  SETUP SIEM — Tablas adicionales
--  Ejecutar: mysql -u root -p sistema_logs < setup_siem.sql
-- ═══════════════════════════════════════════════════════

USE sistema_logs;

-- Alertas configuradas por el administrador
CREATE TABLE IF NOT EXISTS siem_alertas (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  nombre        VARCHAR(100) NOT NULL,
  tipo          VARCHAR(80) NOT NULL,
  threshold     INT DEFAULT 5 COMMENT 'Número de eventos para disparar la alerta',
  ventana_seg   INT DEFAULT 60 COMMENT 'Ventana de tiempo en segundos',
  activa        TINYINT(1) DEFAULT 1,
  accion        VARCHAR(30) DEFAULT 'notificar',
  creada_en     DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_tipo (tipo)
) ENGINE=InnoDB;

-- Migrar tipo de ENUM a VARCHAR en instalaciones existentes
SET @col_type = (
  SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME   = 'siem_alertas'
    AND COLUMN_NAME  = 'tipo'
);
SET @sql = IF(@col_type = 'enum',
  'ALTER TABLE siem_alertas MODIFY COLUMN tipo VARCHAR(80) NOT NULL, MODIFY COLUMN accion VARCHAR(30) DEFAULT ''notificar''',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Añadir unique key si no existe
SET @idx = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='siem_alertas' AND INDEX_NAME='uq_tipo');
SET @sql2 = IF(@idx = 0,
  'ALTER TABLE siem_alertas ADD UNIQUE KEY uq_tipo (tipo)',
  'SELECT 1'
);
PREPARE stmt FROM @sql2; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Eventos detectados por el SIEM
CREATE TABLE IF NOT EXISTS siem_eventos (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  tipo          VARCHAR(50) NOT NULL,
  severidad     ENUM('info','low','medium','high','critical') DEFAULT 'medium',
  titulo        VARCHAR(200) NOT NULL,
  detalle       TEXT,
  ip_origen     VARCHAR(45),
  usuario       VARCHAR(100),
  proceso       VARCHAR(200),
  hash_archivo  VARCHAR(64),
  remediado     TINYINT(1) DEFAULT 0,
  remediacion   TEXT,
  fecha         DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Resultados de análisis VirusTotal
CREATE TABLE IF NOT EXISTS siem_virustotal (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  hash          VARCHAR(64) NOT NULL,
  nombre        VARCHAR(200),
  resultado     TEXT COMMENT 'JSON con resultado VT',
  positivos     INT DEFAULT 0,
  total         INT DEFAULT 0,
  veredicto     ENUM('limpio','sospechoso','malware','desconocido') DEFAULT 'desconocido',
  fecha         DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY (hash)
) ENGINE=InnoDB;

-- Configuración global del SIEM
CREATE TABLE IF NOT EXISTS siem_config (
  clave         VARCHAR(100) PRIMARY KEY,
  valor         TEXT,
  descripcion   VARCHAR(200)
) ENGINE=InnoDB;

INSERT IGNORE INTO siem_config (clave, valor, descripcion) VALUES
  ('vt_api_key',         '',      'API Key de VirusTotal'),
  ('alerta_email',       '',      'Email para notificaciones'),
  ('modo_activo',        '1',     'SIEM activo (1) o pasivo (0)'),
  ('bloqueo_automatico', '0',     'Bloquear IPs automáticamente');

-- Alertas por defecto
INSERT IGNORE INTO siem_alertas (id, nombre, tipo, threshold, ventana_seg, accion) VALUES
  (1, 'Brute Force Login',         'login_fallido',       5,  60,  'bloquear_ip'),
  (2, 'Software instalado',        'software_instalado',  1,  300, 'notificar'),
  (3, 'Proceso sospechoso',        'proceso_sospechoso',  1,  60,  'notificar'),
  (4, 'Conexión externa inusual',  'conexion_externa',    1,  60,  'notificar'),
  (5, 'CPU crítica',               'cpu_alta',            90, 60,  'notificar'),  -- threshold = 90% de uso
  (6, 'Malware detectado',         'malware',             1,  60,  'matar_proceso');

-- ═══════════════════════════════════════════════
--  ALERTAS AVANZADAS SIEM
-- ═══════════════════════════════════════════════

INSERT IGNORE INTO siem_alertas (id, nombre, tipo, threshold, ventana_seg, activa, accion) VALUES
-- Identidad y acceso
(10, 'Login geográficamente imposible',         'geo_imposible',         1,   300,  1, 'notificar'),
(11, 'Acceso en horario inusual',               'horario_inusual',       1,   60,   1, 'notificar'),
(12, 'Cuenta inactiva más de 30 días usada',    'cuenta_inactiva',       1,   60,   1, 'notificar'),
(13, 'Password Spraying',                       'password_spraying',     5,   60,   1, 'bloquear_ip'),
(14, 'Credenciales en texto claro',             'credencial_clara',      1,   60,   1, 'notificar'),
(15, 'Reset de contraseña sin solicitud',       'reset_sin_solicitud',   1,   300,  1, 'notificar'),
(16, 'Cambio masivo de contraseñas AD',         'cambio_masivo_pass',    3,   300,  1, 'notificar'),
(17, 'Usuario con privilegios creado en AD',    'usuario_admin_ad',      1,   60,   1, 'notificar'),
(18, 'Pass the Hash detectado',                 'pass_the_hash',         1,   60,   1, 'notificar'),
(19, 'Anomalía Kerberos',                       'kerberos_anomalia',     2,   60,   1, 'notificar'),
(20, 'DCSync Attack',                           'dcsync',                1,   60,   1, 'notificar'),
-- Red y tráfico
(21, 'Escaneo de puertos detectado',            'port_scan',             15,  10,   1, 'bloquear_ip'),
(22, 'Pico de tráfico saliente',                'trafico_saliente',      1,   60,   1, 'notificar'),
(23, 'Conexión a dominio C2',                   'conexion_c2',           1,   60,   1, 'bloquear_ip'),
(24, 'Beaconing detectado',                     'beaconing',             5,   300,  1, 'notificar'),
(25, 'Enumeración SMB',                         'smb_enum',              3,   30,   1, 'bloquear_ip'),
(26, 'Túnel DNS detectado',                     'dns_tunnel',            10,  60,   1, 'notificar'),
(27, 'Transferencia masiva ICMP',               'icmp_masivo',           50,  10,   1, 'notificar'),
(28, 'User-Agent sospechoso',                   'useragent_sospechoso',  1,   60,   1, 'notificar'),
(29, 'Conexión directa a IP sin DNS',           'conexion_sin_dns',      3,   60,   1, 'notificar'),
-- Sistema y persistencia
(30, 'Modificación archivos críticos sistema',  'archivo_critico',       1,   60,   1, 'notificar'),
(31, 'Modificación Sticky Keys',                'sticky_keys',           1,   60,   1, 'notificar'),
(32, 'Abuso tareas programadas',                'tarea_programada',      1,   60,   1, 'notificar'),
(33, 'Modificación DLL Search Order',           'dll_hijack',            1,   60,   1, 'notificar'),
(34, 'Desactivación herramientas seguridad',    'seguridad_desactivada', 1,   60,   1, 'notificar'),
(35, 'Borrado de logs de eventos',              'logs_borrados',         1,   60,   1, 'notificar'),
(36, 'Desactivación Shadow Copies',             'shadow_copy_delete',    1,   60,   1, 'notificar'),
(37, 'Modificación archivo hosts',              'hosts_modificado',      1,   60,   1, 'notificar'),
(38, 'Cambios en políticas de grupo GPO',       'gpo_cambio',            1,   300,  1, 'notificar'),
-- Panel web
(39, 'Brute Force en panel de login web',       'login_fallido',         10,  60,   1, 'bloquear_ip');

-- Tabla de alertas KQL personalizadas
CREATE TABLE IF NOT EXISTS siem_alertas_kql (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  nombre       VARCHAR(200) NOT NULL,
  descripcion  TEXT,
  kql_query    TEXT NOT NULL COMMENT 'Query en formato KQL/PowerShell',
  threshold    INT DEFAULT 1,
  ventana_seg  INT DEFAULT 60,
  severidad    ENUM('info','low','medium','high','critical') DEFAULT 'medium',
  activa       TINYINT(1) DEFAULT 1,
  accion       ENUM('notificar','bloquear_ip','matar_proceso','ninguna') DEFAULT 'notificar',
  creada_en    DATETIME DEFAULT CURRENT_TIMESTAMP,
  ultima_exec  DATETIME NULL
) ENGINE=InnoDB;

-- Ejecutar cada ALTER por separado para evitar errores si ya existen

-- Columnas extra en siem_eventos (se ignoran si ya existen)
SET @db = DATABASE();
SET @t  = 'siem_eventos';

SET @sql = IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME='falso_positivo')=0,
  'ALTER TABLE siem_eventos ADD COLUMN falso_positivo TINYINT(1) DEFAULT 0',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME='archivado')=0,
  'ALTER TABLE siem_eventos ADD COLUMN archivado TINYINT(1) DEFAULT 0',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME=@t AND COLUMN_NAME='atribuido_a')=0,
  'ALTER TABLE siem_eventos ADD COLUMN atribuido_a VARCHAR(200) NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT 'SIEM actualizado correctamente.' AS resultado;

-- ═══════════════════════════════════════════════
--  COLUMNAS Y TABLAS ADICIONALES
-- ═══════════════════════════════════════════════


-- Tabla de alertas personalizadas KQL
CREATE TABLE IF NOT EXISTS siem_alertas_kql (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  nombre        VARCHAR(150) NOT NULL,
  descripcion   TEXT,
  kql_query     TEXT NOT NULL COMMENT 'Consulta KQL/SQL equivalente',
  threshold     INT DEFAULT 1 COMMENT 'Número de resultados para disparar',
  ventana_seg   INT DEFAULT 60,
  severidad     ENUM('info','low','medium','high','critical') DEFAULT 'medium',
  activa        TINYINT(1) DEFAULT 1,
  accion        ENUM('notificar','bloquear_ip','matar_proceso','ninguna') DEFAULT 'notificar',
  ultimo_disparo DATETIME,
  creada_en     DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ═══════════════════════════════════════════════════════
--  TABLA DE EXCLUSIONES (whitelist)
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS siem_exclusiones (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  tipo        ENUM('ip','usuario','proceso','dominio') NOT NULL,
  valor       VARCHAR(255) NOT NULL,
  descripcion VARCHAR(200) NULL,
  alerta_id   INT NULL COMMENT 'NULL = excluir de todas las alertas',
  activa      TINYINT(1) DEFAULT 1,
  creada_en   DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY (tipo, valor, alerta_id)
) ENGINE=InnoDB;

SELECT 'Tabla siem_exclusiones creada.' AS resultado;

-- ═══════════════════════════════════════════════════════
--  EXCLUSIONES (WHITELIST) PARA ALERTAS
-- ═══════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS siem_exclusiones (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  tipo        ENUM('ip','usuario','proceso','dominio','red') NOT NULL,
  valor       VARCHAR(200) NOT NULL,
  descripcion VARCHAR(200),
  alerta_id   INT NULL COMMENT 'NULL = aplica a todas las alertas',
  activa      TINYINT(1) DEFAULT 1,
  creada_en   DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY (tipo, valor, alerta_id)
) ENGINE=InnoDB;

-- Exclusiones por defecto (IPs y usuarios del sistema)
INSERT IGNORE INTO siem_exclusiones (tipo, valor, descripcion, alerta_id) VALUES
('ip',      '127.0.0.1',  'Loopback local',           NULL),
('ip',      '::1',        'Loopback IPv6',             NULL),
('usuario', 'SYSTEM',     'Cuenta del sistema',        NULL),
('usuario', 'LOCAL SERVICE', 'Servicio local',         NULL),
('usuario', 'NETWORK SERVICE', 'Servicio de red',      NULL),
('proceso', 'svchost',    'Proceso del sistema',       NULL),
('proceso', 'lsass',      'Proceso de autenticación',  NULL);

SELECT 'Exclusiones configuradas.' AS resultado;