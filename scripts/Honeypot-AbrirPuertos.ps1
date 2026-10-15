# =============================================================================
# Honeypot-AbrirPuertos.ps1
# Descripción : Comprueba y abre en el Firewall de Windows los puertos
#               típicos de un honeypot (TCP entrante).
# Requisitos  : PowerShell como Administrador en Windows Server
# =============================================================================

#Requires -RunAsAdministrator

# ─────────────────────────────────────────────────────────────────────────────
# LISTA DE PUERTOS Y SU DESCRIPCIÓN
# ─────────────────────────────────────────────────────────────────────────────
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
Write-Host "`n═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   HONEYPOT - Comprobación y apertura de puertos" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════`n" -ForegroundColor Cyan

$Abiertos  = 0
$Creados   = 0
$Errores   = 0

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

# ─────────────────────────────────────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   RESUMEN" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Ya estaban abiertos : $Abiertos"
Write-Host "  Reglas creadas      : $Creados" -ForegroundColor Green
Write-Host "  Errores             : $Errores"  -ForegroundColor $(if ($Errores -gt 0) { "Red" } else { "White" })

Write-Host "`n[INFO] Para ver todas las reglas del honeypot ejecuta:" -ForegroundColor DarkCyan
Write-Host "  Get-NetFirewallRule | Where-Object { `$_.DisplayName -like 'HONEYPOT*' } | Format-Table DisplayName, Enabled`n" -ForegroundColor DarkCyan

Write-Host "[INFO] Para eliminar todas las reglas del honeypot ejecuta:" -ForegroundColor DarkCyan
Write-Host "  Get-NetFirewallRule | Where-Object { `$_.DisplayName -like 'HONEYPOT*' } | Remove-NetFirewallRule`n" -ForegroundColor DarkCyan