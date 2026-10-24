# generar-cert.ps1
# Genera un certificado SSL autofirmado para pruebas
# Ejecutar como Administrador en PowerShell

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
$pfxPass = ConvertTo-SecureString -String "temp1234" -Force -AsPlainText

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

Write-Host "Puerto 443 y 80 abiertos en el Firewall." -ForegroundColor Green
Write-Host "`n✅ Listo. Ahora ejecuta: node server.js`n" -ForegroundColor Cyan
