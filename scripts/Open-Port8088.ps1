# ============================================================
# Open-Port8088.ps1
# Abre el puerto 8088 (TCP y UDP) en Windows Server 2016
# Ejecutar como Administrador
# ============================================================

$Port        = 8088
$RuleName    = "Puerto $Port - App"
$Description = "Regla creada automaticamente para abrir el puerto $Port"

Write-Host "`n[*] Abriendo puerto $Port en el Firewall de Windows..." -ForegroundColor Cyan

# --- Regla de ENTRADA (Inbound) ---
New-NetFirewallRule `
    -DisplayName "$RuleName (TCP Inbound)" `
    -Description  $Description `
    -Direction    Inbound `
    -Protocol     TCP `
    -LocalPort    $Port `
    -Action       Allow `
    -Profile      Any `
    -Enabled      True

New-NetFirewallRule `
    -DisplayName "$RuleName (UDP Inbound)" `
    -Description  $Description `
    -Direction    Inbound `
    -Protocol     UDP `
    -LocalPort    $Port `
    -Action       Allow `
    -Profile      Any `
    -Enabled      True

# --- Regla de SALIDA (Outbound) ---
New-NetFirewallRule `
    -DisplayName "$RuleName (TCP Outbound)" `
    -Description  $Description `
    -Direction    Outbound `
    -Protocol     TCP `
    -LocalPort    $Port `
    -Action       Allow `
    -Profile      Any `
    -Enabled      True

New-NetFirewallRule `
    -DisplayName "$RuleName (UDP Outbound)" `
    -Description  $Description `
    -Direction    Outbound `
    -Protocol     UDP `
    -LocalPort    $Port `
    -Action       Allow `
    -Profile      Any `
    -Enabled      True

Write-Host "`n[OK] Reglas creadas correctamente." -ForegroundColor Green

# --- Verificacion ---
Write-Host "`n[*] Verificando reglas para el puerto $Port :`n" -ForegroundColor Cyan

Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*$Port*" } |
    Select-Object DisplayName, Direction, Action, Enabled |
    Format-Table -AutoSize