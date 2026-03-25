# compilar.ps1
# Compila el payload y opcionalmente lo envia a la PS4
#
# Uso:
#   .\compilar.ps1                    <- solo compila
#   .\compilar.ps1 -Enviar            <- compila y envia
#   .\compilar.ps1 -Enviar -IP 192.168.1.219

param(
    [switch]$Enviar,
    [string]$IP = "192.168.1.219",
    [int]$BinLoaderPort = 9090,
    [int]$PayloadPort = 12800
)

$ErrorActionPreference = "Stop"

Write-Host "=== PKGSender Payload v9.24 ===" -ForegroundColor Cyan

# Compilar
Write-Host "`n[1] Compilando con Docker..." -ForegroundColor Yellow
docker run --rm -v "${PWD}:/project" ps4-payload-sdk make -C /project
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: compilacion fallida" -ForegroundColor Red
    exit 1
}

$binPath = ".\pkgsender.bin"
if (-not (Test-Path $binPath)) {
    Write-Host "ERROR: no se genero pkgsender.bin" -ForegroundColor Red
    exit 1
}

$size = (Get-Item $binPath).Length
Write-Host "  OK: pkgsender.bin ($([math]::Round($size/1024)) KB)" -ForegroundColor Green

if (-not $Enviar) {
    Write-Host "`nPara enviar: .\compilar.ps1 -Enviar [-IP <PS4_IP>]" -ForegroundColor Gray
    exit 0
}

# Intentar cerrar instancia anterior
Write-Host "`n[2] Cerrando instancia anterior en $IP`:$PayloadPort..." -ForegroundColor Yellow
try {
    Invoke-WebRequest "http://${IP}:${PayloadPort}/shutdown" -TimeoutSec 2 -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 1
    Write-Host "  OK: instancia anterior cerrada" -ForegroundColor Green
} catch {
    Write-Host "  (no habia instancia activa)" -ForegroundColor Gray
}

# Enviar al BinLoader
Write-Host "`n[3] Enviando a BinLoader $IP`:$BinLoaderPort..." -ForegroundColor Yellow
try {
    $bin = [System.IO.File]::ReadAllBytes($binPath)
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect($IP, $BinLoaderPort)
    $stream = $tcp.GetStream()
    $stream.Write($bin, 0, $bin.Length)
    $stream.Flush()
    Start-Sleep -Seconds 1
    $stream.Close()
    $tcp.Close()
    Write-Host "  OK: $($bin.Length) bytes enviados" -ForegroundColor Green
} catch {
    Write-Host "  ERROR al enviar: $_" -ForegroundColor Red
    exit 1
}

# Esperar y verificar
Write-Host "`n[4] Esperando activacion del servidor..." -ForegroundColor Yellow
Start-Sleep -Seconds 4

try {
    $resp = Invoke-WebRequest "http://${IP}:${PayloadPort}/ping" -TimeoutSec 5
    $json = $resp.Content | ConvertFrom-Json
    Write-Host "  ACTIVO: $($json.service) v$($json.version)" -ForegroundColor Green
    Write-Host "  Puerto: $($json.port)" -ForegroundColor Green
} catch {
    Write-Host "  AVISO: servidor no responde aun (puede tardar unos segundos)" -ForegroundColor Yellow
}

Write-Host "`n=== Listo ===" -ForegroundColor Cyan
