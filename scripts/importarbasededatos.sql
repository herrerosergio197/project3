-- ============================================
--  Base de datos: usuarios
--  Tabla: users
--  Contraseñas hasheadas en BASE64
-- ============================================

CREATE DATABASE IF NOT EXISTS usuarios
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE usuarios;

-- --------------------------------------------
--  Tabla: users
-- --------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id       INT            NOT NULL AUTO_INCREMENT,
    user     VARCHAR(50)    NOT NULL UNIQUE,
    name     VARCHAR(100)   NOT NULL,
    surname  VARCHAR(100)   NOT NULL,
    password VARCHAR(255)   NOT NULL,          -- Almacenada en Base64
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------
--  5 usuarios de ejemplo
--  Contraseñas originales ? Base64:
--    MiClave123   ? TWlDbGF2ZTEyMw==
--    Segura456!   ? U2VndXJhNDU2IQ==
--    Password789  ? UGFzc3dvcmQ3ODk=
--    Admin2024#   ? QWRtaW4yMDI0Iw==
--    Hello@World  ? SGVsbG9AV29ybGQ=
-- --------------------------------------------
INSERT INTO users (user, name, surname, password) VALUES
    ('jgarcia',   'Juan',    'Garcia Lopez',    'TWlDbGF2ZTEyMw=='),
    ('mrodriguez', 'Maria',   'Rodriguez Perez', 'U2VndXJhNDU2IQ=='),
    ('clopez',    'Carlos',  'Lopez Martinez',  'UGFzc3dvcmQ3ODk='),
    ('amoreno',   'Ana',     'Moreno Sanchez',  'QWRtaW4yMDI0Iw=='),
    ('ljimenez',  'Laura',   'Jimenez Torres',  'SGVsbG9AV29ybGQ=');

-- --------------------------------------------
--  Verificación
-- --------------------------------------------
SELECT * FROM users;