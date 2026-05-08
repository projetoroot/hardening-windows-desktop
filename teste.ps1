# =========================================================
# Windows Lite
# Compatível:
# Windows 10 e Windows 11
#
# Objetivo:
# - Reduzir uso de RAM
# - Reduzir uso de disco
# - Melhorar desempenho em HD mecânico
# - Remover bloatware
# - Manter estabilidade e updates
# =========================================================

# =========================================================
# EXECUÇÃO COMO ADMIN
# =========================================================

if (-not ([Security.Principal.WindowsPrincipal] `
[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host ""
    Write-Host "Execute este script como Administrador." -ForegroundColor Red
    Write-Host ""

    Pause
    Exit
}

Clear-Host

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Windows Lightweight Optimization Script"
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# =========================================================
# DETECTAR WINDOWS
# =========================================================

$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$osBuild = $osInfo.BuildNumber

Write-Host "Sistema detectado:"
Write-Host "$osName"
Write-Host "Build: $osBuild"
Write-Host ""

$IsWindows11 = $false

if ([int]$osBuild -ge 22000) {
    $IsWindows11 = $true
}

if ($IsWindows11) {
    Write-Host "Windows 11 detectado." -ForegroundColor Yellow
}
else {
    Write-Host "Windows 10 detectado." -ForegroundColor Yellow
}

Write-Host ""

# =========================================================
# DESABILITAR SERVIÇOS
# =========================================================

Write-Host "Desabilitando serviços desnecessários..." -ForegroundColor Cyan
Write-Host ""

$services = @(
    "SysMain",
    "WSearch",
    "DiagTrack",
    "dmwappushservice",
    "MapsBroker",
    "Fax",
    "RetailDemo"
)

foreach ($svc in $services) {

    $serviceExists = Get-Service -Name $svc -ErrorAction SilentlyContinue

    if ($serviceExists) {

        Write-Host "Configurando serviço: $svc"

        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

Write-Host ""

# =========================================================
# REMOVER APPS UWP
# =========================================================

Write-Host "Removendo aplicativos desnecessários..." -ForegroundColor Cyan
Write-Host ""

$apps = @(
    "*Xbox*",
    "*XboxGamingOverlay*",
    "*XboxSpeechToTextOverlay*",
    "*XboxIdentityProvider*",
    "*ZuneMusic*",
    "*ZuneVideo*",
    "*BingNews*",
    "*BingWeather*",
    "*GetHelp*",
    "*Getstarted*",
    "*People*",
    "*WindowsMaps*",
    "*Teams*",
    "*Clipchamp*",
    "*Solitaire*",
    "*SkypeApp*",
    "*OfficeHub*"
)

foreach ($app in $apps) {

    Write-Host "Removendo: $app"

    Get-AppxPackage -AllUsers $app |
    Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

    Get-AppxProvisionedPackage -Online |
    Where-Object {$_.DisplayName -like $app} |
    Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

Write-Host ""

# =========================================================
# DESABILITAR HIBERNAÇÃO
# =========================================================

Write-Host "Desabilitando hibernação..." -ForegroundColor Cyan

powercfg -h off

Write-Host ""

# =========================================================
# AJUSTAR EFEITOS VISUAIS
# =========================================================

Write-Host "Ajustando efeitos visuais..." -ForegroundColor Cyan

Set-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" `
-Name VisualFXSetting `
-Type DWord `
-Value 2 `
-ErrorAction SilentlyContinue

Write-Host ""

# =========================================================
# DESABILITAR TRANSPARÊNCIA
# =========================================================

Write-Host "Desabilitando transparência..." -ForegroundColor Cyan

Set-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" `
-Name EnableTransparency `
-Type DWord `
-Value 0 `
-ErrorAction SilentlyContinue

Write-Host ""

# =========================================================
# DESABILITAR TELEMETRIA
# =========================================================

Write-Host "Desabilitando telemetria..." -ForegroundColor Cyan

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
/v AllowTelemetry `
/t REG_DWORD `
/d 0 `
/f | Out-Null

Write-Host ""

# =========================================================
# DESABILITAR SUGESTÕES
# =========================================================

Write-Host "Desabilitando sugestões do Windows..." -ForegroundColor Cyan

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
/v SilentInstalledAppsEnabled `
/t REG_DWORD `
/d 0 `
/f | Out-Null

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
/v SystemPaneSuggestionsEnabled `
/t REG_DWORD `
/d 0 `
/f | Out-Null

Write-Host ""

# =========================================================
# WINDOWS 11
# =========================================================

if ($IsWindows11) {

    Write-Host "Aplicando otimizações específicas do Windows 11..." -ForegroundColor Cyan
    Write-Host ""

    # -----------------------------------------------------
    # DESABILITAR WIDGETS
    # -----------------------------------------------------

    reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" `
    /v AllowNewsAndInterests `
    /t REG_DWORD `
    /d 0 `
    /f | Out-Null

    # -----------------------------------------------------
    # DESABILITAR COPILOT
    # -----------------------------------------------------

    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" `
    /v TurnOffWindowsCopilot `
    /t REG_DWORD `
    /d 1 `
    /f | Out-Null
}

Write-Host ""

# =========================================================
# DESABILITAR TAREFAS DE TELEMETRIA
# =========================================================

Write-Host "Desabilitando tarefas agendadas..." -ForegroundColor Cyan

Get-ScheduledTask |
Where-Object {
    $_.TaskName -like "*Telemetry*" -or
    $_.TaskName -like "*Customer Experience*"
} |
Disable-ScheduledTask -ErrorAction SilentlyContinue

Write-Host ""

# =========================================================
# DESABILITAR SMB1
# =========================================================

Write-Host "Desabilitando SMB1..." -ForegroundColor Cyan

Disable-WindowsOptionalFeature `
-Online `
-FeatureName SMB1Protocol `
-NoRestart `
-ErrorAction SilentlyContinue

Write-Host ""

# =========================================================
# LIMPEZA DE COMPONENTES
# =========================================================

Write-Host "Executando limpeza do sistema..." -ForegroundColor Cyan

Dism.exe /online /Cleanup-Image /StartComponentCleanup

Write-Host ""

# =========================================================
# LIMPEZA TEMP
# =========================================================

Write-Host "Limpando arquivos temporários..." -ForegroundColor Cyan

Remove-Item "$env:TEMP\*" `
-Recurse `
-Force `
-ErrorAction SilentlyContinue

Remove-Item "C:\Windows\Temp\*" `
-Recurse `
-Force `
-ErrorAction SilentlyContinue

Write-Host ""

# =========================================================
# FINALIZAÇÃO
# =========================================================

Write-Host "===============================================" -ForegroundColor Green
Write-Host " Otimização concluída"
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""

Write-Host "Recomendações:" -ForegroundColor Yellow
Write-Host ""
Write-Host "- Reinicie o computador"
Write-Host "- Use SSD se possível"
Write-Host "- Mantenha pelo menos 4 GB RAM"
Write-Host ""

Pause
