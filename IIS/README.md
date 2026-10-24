# SysLog Monitor — Windows Server 2016 · HTTPS · Puerto 443

## Archivos incluidos

| Archivo                 | Descripción                                        |
|-------------------------|----------------------------------------------------|
| `index.html`            | Página web (login + visor de logs)                 |
| `server.js`             | Backend Node.js con HTTPS en el puerto 443         |
| `setup_bd.sql`          | Script SQL para crear la base de datos             |
| `generar-cert.ps1`      | Genera certificado SSL autofirmado                 |
| `instalar-servicio.js`  | Registra el servidor como servicio de Windows      |

---

## Credenciales de acceso

| Usuario | Contraseña |
|---------|------------|
| `root`  | `Admin1234`|

---

## Instalación paso a paso

### Requisito previo: Node.js
Descarga e instala Node.js LTS desde https://nodejs.org
Asegúrate de que Node.js está en el PATH del sistema.

---

### Paso 1 — Instalar dependencias

Abre **PowerShell como Administrador** en la carpeta del proyecto:

```powershell
npm install express mysql2 bcryptjs cors
```

---

### Paso 2 — Crear la base de datos MySQL

```powershell
mysql -u root -p < setup_bd.sql
```

Si tu MySQL tiene contraseña, editala también en `server.js`:
```js
const DB_CONFIG = {
  host:     'localhost',
  user:     'root',
  password: 'TU_PASSWORD_MYSQL',  // ← contraseña de MySQL
  database: 'sistema_logs',
};
```

---

### Paso 3 — Configurar el certificado SSL

#### Opción A — Certificado autofirmado (para pruebas internas)

Ejecuta en PowerShell como Administrador:
```powershell
.\generar-cert.ps1 -Dominio "tudominio.com"
```

Esto genera `server.crt` y `server.key` en la carpeta del proyecto
y abre automáticamente el puerto 443 en el Firewall de Windows.

#### Opción B — Certificado real con Let's Encrypt (recomendado para producción)

1. Descarga **win-acme** desde https://www.win-acme.com
2. Ejecuta `wacs.exe` y sigue el asistente para tu dominio
3. Copia los archivos generados como `server.crt` y `server.key`

#### Opción C — Certificado corporativo

Coloca tus archivos `server.crt` y `server.key` en la carpeta del proyecto.

---

### Paso 4 — Abrir el puerto 443 en el Firewall

Si no ejecutaste `generar-cert.ps1`, ábrelo manualmente:

```powershell
# Puerto HTTPS
netsh advfirewall firewall add rule name="SysLog HTTPS" dir=in action=allow protocol=TCP localport=443

# Puerto HTTP (redirige a HTTPS automáticamente)
netsh advfirewall firewall add rule name="SysLog HTTP" dir=in action=allow protocol=TCP localport=80
```

---

### Paso 5 — Arrancar el servidor

```powershell
node server.js
```

Si los certificados están correctamente configurados verás:
```
[HTTP]  Redirigiendo puerto 80 → HTTPS
✅ Servidor HTTPS arrancado en https://localhost:443
```

Accede desde el navegador: `https://tudominio.com`

---

### Paso 6 (Opcional) — Instalar como servicio de Windows

Para que el servidor arranque automáticamente con Windows:

```powershell
npm install -g node-windows
npm link node-windows
node instalar-servicio.js
```

Puedes gestionar el servicio desde `services.msc` con el nombre **SysLog Monitor**.

---

## Solución de problemas

| Problema | Solución |
|----------|----------|
| Puerto 443 en uso | Comprueba con `netstat -ano \| findstr :443` |
| Error de certificado | Verifica que `server.crt` y `server.key` existen en la carpeta |
| Error de conexión MySQL | Comprueba usuario/contraseña en `server.js` |
| Logs vacíos | Ejecuta PowerShell como Administrador |
| El navegador advierte "no seguro" | Certificado autofirmado; usa Let's Encrypt para producción |
