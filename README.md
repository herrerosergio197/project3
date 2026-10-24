
## SIEM+WEB+CTF


Instalación básica del entorno completo

----------------------------------------------------------------------------------------------------------

Creación de usuarios y ordenadores como en el ejemplo:


```powershell
$DomainDN       = "DC=herrerosergio197,DC=test"               # Distinguished Name del dominio
$UserOU         = "CN=Users,DC=herrerosergio197,DC=test"      # Contenedor Users por defecto
$ComputerOU     = "CN=Computers,DC=herrerosergio197,DC=test"  # Carpeta destino para ordenadores
$DefaultPwd     = "************"                              # Contraseña inicial 
$UPNSuffix      = "herrerosergio197.test"                     # Sufijo UPN
# ─────────────────────────────────────────────────────────────────────────────
# DATOS DE LOS 10 USUARIOS
# Campos: Nombre, Apellido, Departamento, Cargo
# ─────────────────────────────────────────────────────────────────────────────
$Usuarios = @(
    [PSCustomObject]@{ Nombre = "Carlos";    Apellido = "Rodríguez";  Departamento = "IT";           Cargo = "Administrador de Sistemas" },
    [PSCustomObject]@{ Nombre = "Laura";     Apellido = "Martínez";   Departamento = "RRHH";         Cargo = "Técnica de Recursos Humanos" },
    [PSCustomObject]@{ Nombre = "Javier";    Apellido = "López";      Departamento = "Contabilidad"; Cargo = "Contable Senior" },
    [PSCustomObject]@{ Nombre = "María";     Apellido = "Sánchez";    Departamento = "Marketing";    Cargo = "Responsable de Marketing" },
    [PSCustomObject]@{ Nombre = "Alejandro"; Apellido = "García";     Departamento = "Ventas";       Cargo = "Agente Comercial" },
    [PSCustomObject]@{ Nombre = "Sofía";     Apellido = "Fernández";  Departamento = "IT";           Cargo = "Desarrolladora de Software" },
    [PSCustomObject]@{ Nombre = "Miguel";    Apellido = "González";   Departamento = "Logística";    Cargo = "Coordinador de Logística" },
    [PSCustomObject]@{ Nombre = "Elena";     Apellido = "Torres";     Departamento = "Legal";        Cargo = "Asesora Jurídica" },
    [PSCustomObject]@{ Nombre = "Pablo";     Apellido = "Díaz";       Departamento = "Soporte";      Cargo = "Técnico de Soporte" },
    [PSCustomObject]@{ Nombre = "Isabel";    Apellido = "Moreno";     Departamento = "Dirección";    Cargo = "Directora de Operaciones" }
)

# ─────────────────────────────────────────────────────────────────────────────
# DATOS DE LOS 10 ORDENADORES
# ─────────────────────────────────────────────────────────────────────────────
$Ordenadores = @(
    "PC-CARLOS01",
    "PC-LAURA01",
    "PC-JAVIER01",
    "PC-MARIA01",
    "PC-ALEJANDRO01",
    "PC-SOFIA01",
    "PC-MIGUEL01",
    "PC-ELENA01",
    "PC-PABLO01",
    "PC-ISABEL01"
)

# ─────────────────────────────────────────────────────────────────────────────
# FUNCIÓN AUXILIAR: Normalizar texto (quita tildes y ñ para el SAMAccountName)
# ─────────────────────────────────────────────────────────────────────────────
function Remove-Diacritics {
    param([string]$Text)
    $normalized = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($c in $normalized.ToCharArray()) {
        $cat = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($c)
        if ($cat -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($c)
        }
    }
    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC)
}

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTACIÓN DE USUARIOS
# ─────────────────────────────────────────────────────────────────────────────
$SecurePassword = ConvertTo-SecureString $DefaultPwd -AsPlainText -Force

foreach ($User in $Usuarios) {

    # — Construir campos derivados
    $NombreNorm   = Remove-Diacritics -Text $User.Nombre
    $ApellidoNorm = Remove-Diacritics -Text $User.Apellido
    $SAMAccount   = ($NombreNorm.Substring(0,1) + $ApellidoNorm).ToLower() -replace '\s',''
    $UPN          = "$SAMAccount@$UPNSuffix"
    $NombreCompleto = "$($User.Nombre) $($User.Apellido)"
    $NombreMostrar  = "$($User.Nombre) $($User.Apellido)"  # DisplayName

    # — Comprobar si el usuario ya existe
    if (Get-ADUser -Filter { SamAccountName -eq $SAMAccount } -ErrorAction SilentlyContinue) {
        Write-Host "[OMITIDO]  El usuario '$SAMAccount' ya existe en el directorio." -ForegroundColor Yellow
        continue
    }

    try {
        New-ADUser `
            -SamAccountName        $SAMAccount `
            -UserPrincipalName     $UPN `
            -GivenName             $User.Nombre `
            -Surname               $User.Apellido `
            -Name                  $NombreCompleto `
            -DisplayName           $NombreMostrar `
            -Department            $User.Departamento `
            -Title                 $User.Cargo `
            -AccountPassword       $SecurePassword `
            -ChangePasswordAtLogon $true `
            -Enabled               $true `
            -Path                  $UserOU `
            -ErrorAction Stop

        Write-Host "[OK]  Usuario creado : $NombreCompleto  ($SAMAccount)" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR]  No se pudo crear '$SAMAccount': $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTACIÓN DE ORDENADORES
# ────────────────────────────────────────────────────────────────────────────-
foreach ($PC in $Ordenadores) {

    # — Comprobar si el objeto de equipo ya existe
    if (Get-ADComputer -Filter { Name -eq $PC } -ErrorAction SilentlyContinue) {
        Write-Host "[OMITIDO]  El ordenador '$PC' ya existe en el directorio." -ForegroundColor Yellow
        continue
    }

    try {
        New-ADComputer `
            -Name        $PC `
            -SAMAccountName "$PC$" `
            -Path        $ComputerOU `
            -Enabled     $true `
            -ErrorAction Stop

        Write-Host "[OK]  Ordenador creado : $PC" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR]  No se pudo crear '$PC': $($_.Exception.Message)" -ForegroundColor Red
    }
}
```

Creamos un usuario adicional llamado Jordan que será el que contenga la contraseña y flag final dentro del dominio.

----
Abrimos los puertos necesarios para construir el honeypot.
````powershell
$Puertos = @(
    [PSCustomObject]@{ Puerto = 21;    Desc = "FTP" },
    [PSCustomObject]@{ Puerto = 22;    Desc = "SSH" },
    [PSCustomObject]@{ Puerto = 23;    Desc = "Telnet" },
    [PSCustomObject]@{ Puerto = 25;    Desc = "SMTP" },
    [PSCustomObject]@{ Puerto = 80;    Desc = "HTTP" },
    [PSCustomObject]@{ Puerto = 110;   Desc = "POP3" },
    [PSCustomObject]@{ Puerto = 143;   Desc = "IMAP" },
    [PSCustomObject]@{ Puerto = 389;   Desc = "LDAP" },
    [PSCustomObject]@{ Puerto = 443;   Desc = "HTTPS" },
    [PSCustomObject]@{ Puerto = 445;   Desc = "SMB" },
    [PSCustomObject]@{ Puerto = 631;   Desc = "IPP (Impresion)" },
    [PSCustomObject]@{ Puerto = 1080;  Desc = "SOCKS Proxy" },
    [PSCustomObject]@{ Puerto = 1433;  Desc = "MSSQL" },
    [PSCustomObject]@{ Puerto = 1521;  Desc = "Oracle DB" },
    [PSCustomObject]@{ Puerto = 3306;  Desc = "MySQL" },
    [PSCustomObject]@{ Puerto = 3389;  Desc = "RDP" },
    [PSCustomObject]@{ Puerto = 5060;  Desc = "SIP (VoIP)" },
    [PSCustomObject]@{ Puerto = 5432;  Desc = "PostgreSQL" },
    [PSCustomObject]@{ Puerto = 5900;  Desc = "VNC" },
    [PSCustomObject]@{ Puerto = 6379;  Desc = "Redis" },
    [PSCustomObject]@{ Puerto = 6667;  Desc = "IRC" },
    [PSCustomObject]@{ Puerto = 8080;  Desc = "HTTP Alternativo" },
    [PSCustomObject]@{ Puerto = 9100;  Desc = "JetDirect (Impresion)" },
    [PSCustomObject]@{ Puerto = 9200;  Desc = "Elasticsearch" },
    [PSCustomObject]@{ Puerto = 11211; Desc = "Memcached" }
)

# ─────────────────────────────────────────────────────────────────────────────
# CABECERA
# ─────────────────────────────────────────────────────────────────────────────

foreach ($Item in $Puertos) {

    $puerto   = $Item.Puerto
    $desc     = $Item.Desc
    $ruleName = "HONEYPOT - $desc (TCP $puerto)"

    # ── Comprobar si ya existe una regla de entrada para este puerto ──────────
    $reglaExiste = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $ruleName }

    # También comprobar si hay cualquier otra regla activa que ya lo permita
    $otraRegla = Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $puerto -and $_.Protocol -eq "TCP" } |
        ForEach-Object { Get-NetFirewallRule -AssociatedNetFirewallPortFilter $_ -EA 0 } |
        Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and $_.Enabled -eq "True" }

    if ($reglaExiste -or $otraRegla) {
        Write-Host "[YA ABIERTO]  Puerto $puerto/TCP  ($desc)" -ForegroundColor Yellow
        $Abiertos++
        continue
    }

    # ── Crear la regla de entrada ─────────────────────────────────────────────
    try {
        New-NetFirewallRule `
            -DisplayName  $ruleName `
            -Direction    Inbound `
            -Protocol     TCP `
            -LocalPort    $puerto `
            -Action       Allow `
            -Profile      Any `
            -Description  "Honeypot: permite trafico entrante en $desc (TCP $puerto)" `
            -ErrorAction  Stop | Out-Null

        Write-Host "[ABIERTO]     Puerto $puerto/TCP  ($desc) -- regla creada" -ForegroundColor Green
        $Creados++
    }
    catch {
        Write-Host "[ERROR]       Puerto $puerto/TCP  ($desc): $($_.Exception.Message)" -ForegroundColor Red
        $Errores++
    }
}
````
---
FTP
---


## SIEM+WEB+CTF
Habilitamos FTP anónimo con permisos de lectura para el AD ubicado en C:\FTP. Asignamos nuestra ip con el puerto 21.  



## Contraseñas
Creamos el fichero con todas las contraseñas.

````powershell
$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@'
1..2000 | ForEach-Object {
    -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
} | Set-Content passwords.txt
````

## SSH
Instalamos el servidor SSH. 
````powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
````
Editamos el fichero sshd_config y ponemos el protocolo 2 por el puerto 22. \
El nivel de logs que nos lo monitorice (Modo Verbose). \
Permitimos todos los usuarios que se puedan loguear con contraseña en blanco o no. \
*AllowUsers yes \
PasswordAuthentication yes \
PermitEmptyPasswords yes* \

Para forzar password brute force desactivamos Autenticación de clave pública y el fichero de claves autorizadas. \
*PubkeyAuthentication no \
AuthorizedKeysFile none \*

Dejamos 60 segundos y 3 intentos para iniciar sesión. \
Subimos el timeout, los startups y el máximo número de intentos. \
*LoginGraceTime 600 \
MaxStartups 100:30:200 \
PerSourceMaxStartups none \
#PermitRootLogin prohibit-password \
#StrictModes yes \
MaxAuthTries 2000 \
#MaxSessions 10* \
Para quitar el banner y toda la basura que aparece al loguear en ssh corremos los siguientes comandos.
````powershell
Reg add “HKLM\SOFTWARE\OpenSSH” /v DefaultShell /t REG_SZ /d “C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe” /f
reg add “HKLM\SOFTWARE\OpenSSH” /v DefaultShellCommandOption /t REG_SZ /d “-NoLogo” /f
````
Activamos la monitorización de logs en Windows. 
````powershell
Auditpol /set /subcategory:”Logon” /success:enable /failure:enable
````
Para poner contraseñas débiles deberemos cambiar la configuración de complejidad de contraseñas
````powershell
Secedit /export /cfg C:\policy.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg C:\policy.cfg /areas SECURITYPOLICY
````

## Usuarios
Procedemos a crear todos los usuarios con los que se loguearan los usuarios ssh. Ponemos unos usuarios trampa.
````powershell
Net user admin 123456 /add
net user root root /add
net user test test /add
````
Aplicamos los cambiamos
````powershell
Restart-Service sshd
````
Creamos los usuarios reales con sus contraseñas reales para ssh. Tendrán que ir pivotando de uno en otro hasta llegar a zadmin.
````powershell
Net user backup mWifTwWOhmHhELTs /add
net user developer D4l9PKPNxYnIWf@l /add
net user ftpuser UPUwHSIE7Sfsxf9f /add
net user manager 2BYQCqmK7KVHEdli /add
net user soporte tcYWcjwYr7qHWOmy /add
net user usuario uGAA11YrEVg7WiRX /add
net user zadmin Lut8Ez@zOzL5oMWd /add
````
Les restringimos la Shell para que solo sean capaces de ver su carpeta.
````powershell
Icacls “C:\” /deny “UsuariosSSH_Restringidos:(RD)”
icacls “C:\Users” /deny “UsuariosSSH_Restringidos:(RD)”
icacls “C:\SSHData” /deny “UsuariosSSH_Restringidos:(RD)”
````
Ahora para que sean capaces de entrar a su carpeta de SSHData creamos otro script.
````powershell
# 1. Configuración de nombres
$grupo = "UsuariosSSH_Restringidos"
$usuarios = @("admin", "backup", "developer", "ftpuser", "guest", "manager", "root", "soporte", "test", "usuario", "zadmin")
$basePath = "C:\SSHData"

# 2. Limpiar y configurar la carpeta Raíz (C:\SSHData)
# S = Sincronizar, REA = Atributos extendidos, RA = Atributos, RD = Leer datos (mínimo para entrar)
icacls $basePath /inheritance:d
icacls $basePath /grant "Administradores:(OI)(CI)(F)"
icacls $basePath /grant "${grupo}:(S,REA,RA)" 

# 3. Procesar cada usuario de la lista
foreach ($u in $usuarios) {
    $userPath = Join-Path $basePath $u
    
    if (!(Test-Path $userPath)) {
        New-Item -ItemType Directory -Path $userPath -Force | Out-Null
        Write-Host "Carpeta creada para: $u" -ForegroundColor Green
    }
    
    # Resetear permisos de la subcarpeta del usuario
    icacls $userPath /inheritance:d
    icacls $userPath /remove "Usuarios" "Authenticated Users" "Todos" /substitute $null
    
    # Asignar Propiedad y Control Total al usuario específico
    icacls $userPath /setowner $u
    icacls $userPath /grant "${u}:(OI)(CI)(F)"
    icacls $userPath /grant "Administradores:(OI)(CI)(F)"
````

## Base de Datos MySQL
````MySQL
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
````
Definimos log_accesos para que tenga monitorización de todos los accesos a las bases de datos.
````MySQL
SET GLOBAL general_log = ‘ON’;
SET GLOBAL general_log_file = ‘C:/ProgramData/MySQL/MySQL Server 8.0/Data/mysql_general.log’;
````
Modificamos el mysqld para dejar registrados los logs completos. \
*[mysqld] \
basedir="C:/Program Files/MySQL/MySQL Server 8.0" \
datadir="C:/ProgramData/MySQL/MySQL Server 8.0/data" \
general log file = C:/ProgramData/MySQL/Data/mysqlgeneral.log \
slowquery log file = C:/ProgramData/MySQL/Data/mysql_slow.log \
long query time =2*
## Panel WEB
Instalamos dependencias.
````powershell
Npm install express mysql2 bcryptjs cors
````
Creamos los certificados mediante el script que nos ha creado para abrir el Puerto 443 y los certificados.
````powershell
param(
    [string]$Dominio = "localhost",
    [string]$Carpeta = $PSScriptRoot
)

Write-Host "`n=== Generador de Certificado SSL Autofirmado ===" -ForegroundColor Cyan
Write-Host "Dominio: $Dominio" -ForegroundColor Yellow

# Crear certificado en el almacén de Windows
$cert = New-SelfSignedCertificate `
    -DnsName $Dominio, "localhost", "127.0.0.1" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(2) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -FriendlyName "SysLog Monitor SSL"

Write-Host "Certificado creado: $($cert.Thumbprint)" -ForegroundColor Green

# Exportar .CRT (certificado público)
$certPath = Join-Path $Carpeta "server.crt"
$certBase64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
"-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----" | Out-File -FilePath $certPath -Encoding ASCII
Write-Host "Certificado exportado: $certPath" -ForegroundColor Green

# Exportar .KEY (clave privada) vía openssl si está disponible, si no via PFX
$keyPath = Join-Path $Carpeta "server.key"
$pfxPath = Join-Path $Carpeta "server.pfx"
$pfxPass = ConvertTo-SecureString -String "_contraseñaaelegir_" -Force -AsPlainText

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPass | Out-Null
Write-Host "PFX exportado: $pfxPath" -ForegroundColor Green

# Intentar extraer la clave con openssl
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if ($openssl) {
    & openssl pkcs12 -in $pfxPath -nocerts -nodes -out $keyPath -passin pass:temp1234 2>$null
    Write-Host "Clave privada exportada: $keyPath" -ForegroundColor Green
    Remove-Item $pfxPath -Force
} else {
    Write-Host "`n⚠️  OpenSSL no encontrado. Pasos adicionales:" -ForegroundColor Yellow
    Write-Host "  1. Descarga OpenSSL: https://slproweb.com/products/Win32OpenSSL.html"
    Write-Host "  2. Ejecuta este comando para extraer la clave del PFX:"
    Write-Host "     openssl pkcs12 -in server.pfx -nocerts -nodes -out server.key -passin pass:temp1234" -ForegroundColor Cyan
    Write-Host "`n  O instala win-acme para certificados Let's Encrypt reales:"
    Write-Host "     https://www.win-acme.com" -ForegroundColor Cyan
}

# Añadir al Firewall de Windows
Write-Host "`nAbriendo puerto 443 en el Firewall de Windows..." -ForegroundColor Yellow
netsh advfirewall firewall add rule `
    name="SysLog Monitor HTTPS" `
    dir=in action=allow protocol=TCP localport=443 | Out-Null
netsh advfirewall firewall add rule `
    name="SysLog Monitor HTTP redirect" `
    dir=in action=allow protocol=TCP localport=80 | Out-Null
````
Esto nos permite conectarnos a través del puerto 8080 a la página web. Pero queremos el 443. Entonces corremos el siguiente comando para extraer el server.key. \
````powershell
“C:\Program Files\OpenSSL-Win64\bin\openssl.exe” pkcs12 -in server.pfx -nocerts -nodes -out server.key -passin pass:temp1234
````
Ahora nos sale un fichero adicionnal que es el server.key, que es el que nos permite conectarnos por el puerto 443. \
Ejecutamos el comando para conectarnos a la página web.
````powershell
Node server.js
````
Lo configuramos como un proceso nativo que se incia con Windows con los siguientes comandos.
````powershell
Npm install pm2 -g
npm install pm2-windows-startup -g
pm2-startup install
cd C:\IIS
pm2 start server.js –name “SIEM”
pm2 save
````
Añadimos lo siguiente al my.ini en la sección de mysqld.
````mysqld
General_log          = 1
general_log_file     = C:/ProgramData/MySQL/MySQL Server 8.0/Data/mysql_general.log
slow_query_log       = 1
slow_query_log_file  = C:/ProgramData/MySQL/MySQL Server 8.0/Data/mysql_slow.log
long_query_time      = 2
````
## Web Blog Hosteado 2
Hacemos el proceso de inicio automático en la consola DOS.
````cmd
Cd C:\Administrator\public
pm2 start server.js –name “BLOG”
pm2 save
````

## SIEM
Ahora para hacer funcionar el SIEM, deberemos importarlo en la base de datos.
````cmd
Mysql -u root -p sistema_logs < setup_siem.sql
````

## Configuración nueva Servidor
Habilitamos SAMBA en el servidor
````powershell
Get-SmbServerConfiguration \ Select EnableSMB2Protocol, EnableSMB1Protocol
Set-SmbServerConfiguration -EnableSMB2Protocol $true
````
Habilitamos WinRM
````powershell
Enable-PSRemoting -Force
Add-ADGroupMember -Identity "Remote Management Users" -Members "developer"
````
Para el usuario "usuario" usaremos la técnica de Remote Management Users Group.
````powershell
Add-ADGroupMember -Identity "S-1-5-32-580" -Members "usuario"
````