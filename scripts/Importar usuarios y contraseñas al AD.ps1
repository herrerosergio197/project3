# =============================================================================
# Import-AD-Usuarios-Ordenadores.ps1
# Descripción : Importa 10 usuarios y 10 ordenadores en Active Directory
# Requisitos  : Módulo ActiveDirectory, ejecución con privilegios de dominio
# =============================================================================

#Requires -Modules ActiveDirectory

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN GLOBAL  –  Ajusta estos valores a tu entorno
# ─────────────────────────────────────────────────────────────────────────────
$DomainDN       = "DC=herrerosergio197,DC=test"               # Distinguished Name del dominio
$UserOU         = "CN=Users,DC=herrerosergio197,DC=test"      # Contenedor Users por defecto
$ComputerOU     = "CN=Computers,DC=herrerosergio197,DC=test"  # Carpeta destino para ordenadores
$DefaultPwd     = "Empresa2024!" # Contraseña inicial (cámbiala tras el primer inicio de sesión)
$UPNSuffix      = "herrerosergio197.test"                     # Sufijo UPN
# ─────────────────────────────────────────────────────────────────────────────

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
Write-Host "`n═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   IMPORTACIÓN DE USUARIOS EN ACTIVE DIRECTORY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════`n" -ForegroundColor Cyan

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
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   IMPORTACIÓN DE ORDENADORES EN ACTIVE DIRECTORY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════`n" -ForegroundColor Cyan

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

# ─────────────────────────────────────────────────────────────────────────────
# RESUMEN FINAL
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   PROCESO COMPLETADO" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Usuarios intentados  : $($Usuarios.Count)"
Write-Host "  Ordenadores intentados: $($Ordenadores.Count)"
Write-Host "`nRecuerda cambiar la contraseña predeterminada '$DefaultPwd' si es necesario.`n" -ForegroundColor Yellow