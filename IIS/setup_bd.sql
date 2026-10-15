-- ═══════════════════════════════════════════════════════════════
--  SETUP DE BASE DE DATOS — Sistema de Logs
--  Ejecutar con: mysql -u root -p < setup_bd.sql
-- ═══════════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS sistema_logs
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE sistema_logs;

CREATE TABLE IF NOT EXISTS usuarios (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  usuario       VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  nombre        VARCHAR(100) NOT NULL,
  rol           ENUM('admin','operador','visor') DEFAULT 'admin',
  activo        TINYINT(1) DEFAULT 1,
  creado_en     DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS log_accesos (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  usuario_id INT,
  ip         VARCHAR(45),
  accion     VARCHAR(100),
  fecha      DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Usuario: root | Contraseña: Admin1234
INSERT INTO usuarios (usuario, password_hash, nombre, rol) VALUES
(
  'root',
  '$2b$12$kLWL3OCHfLauu3RvkF4frOk4/5LuiXJ5vVPb85MNngqDnaZ0BWIRa',
  'Administrador del Sistema',
  'admin'
),
(
  'jgarcia',
  '$2a$12$77jGvMtutAiosGN/dtp2h.DI/X7xvCerkssJRP8RpueJ9ptjrbDBK',
  'Juan Garcia',
  'visor'
),
(
  'mrodriguez',
  '$2a$12$ak.gcuGRnOd0HGLtxmKfPOS0mTc6YZGi9oJPDaV0oYAzrBRjGysay',
  'Maria Rodriguez',
  'visor'
),
(
  'clopez',
  '$2a$12$Zv9TKiFpbdn5o8pJ71Nhaux588zDVw6BHjaDNfviFJwItBABaSp5m',
  'Carlos Lopez',
  'visor'
),
(
  'amoreno',
  '$2a$12$qC3nwtlZyUvMRjBes8D20O2BGCtE/zPRgz4rK8UzeposuF86kEhBy',
  'Ana Moreno',
  'visor'
),
(
  'ljimenez',
  '$2a$12$FLAV56Kf2mPMXVPnnU25lOXyBMw5s/v8tmrHbpjqAMLR7mrR2Isda',
  'Laura Jimenez',
  'visor'
);

SELECT 'Base de datos configurada correctamente.' AS resultado;
SELECT usuario, nombre, rol FROM usuarios;
