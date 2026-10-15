# 1. Configuración de nombres
$grupo = "UsuariosSSH_Restringidos"
$usuarios = @("admin", "backup", "developer", "ftpuser", "guest", "manager", "root", "soporte", "test", "usuario", "zadmin")
$basePath = "C:\SSHData"

Write-Host "--- Iniciando configuración de permisos para SSH ---" -ForegroundColor Cyan

# 2. Limpiar y configurar la carpeta Raíz (C:\SSHData)
# S = Sincronizar, REA = Atributos extendidos, RA = Atributos, RD = Leer datos (mínimo para entrar)
Write-Host "Configurando carpeta raíz: $basePath"
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

    Write-Host "Aplicando permisos para: $u"
    
    # Resetear permisos de la subcarpeta del usuario
    icacls $userPath /inheritance:d
    icacls $userPath /remove "Usuarios" "Authenticated Users" "Todos" /substitute $null
    
    # Asignar Propiedad y Control Total al usuario específico
    icacls $userPath /setowner $u
    icacls $userPath /grant "${u}:(OI)(CI)(F)"
    icacls $userPath /grant "Administradores:(OI)(CI)(F)"
}

Write-Host "--- Proceso completado con éxito ---" -ForegroundColor Cyan