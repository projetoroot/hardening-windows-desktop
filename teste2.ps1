# =========================================================
# Windows Lite + Lite
# Compatível:
# Windows 10 e Windows 11
#
# Objetivo:
# - Remover bloatware
# - Reduzir RAM/CPU/disco
# - Melhorar desempenho
# - Preservar estabilidade
#
# NÃO remove:
# - Windows Update
# - Defender
# - WinSxS
# - .NET
# - WMI
# - Component Servicing
# =========================================================

# =========================================================
# ADMIN CHECK
# =========================================================

if (-not ([Security.Principal.WindowsPrincipal] `
[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host ""
    Write-Host "Execute como Administrador." -ForegroundColor Red
    Write-Host ""

    Pause
    Exit
}

Clear-Host

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Windows Debloat Optimization"
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# =========================================================
# DETECTAR WINDOWS
# =========================================================

$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$osBuild = [int]$osInfo.BuildNumber

$IsWindows11 = $false

if ($osBuild -ge 22000) {
    $IsWindows11 = $true
}

Write-Host "Sistema:"
Write-Host "$osName"
Write-Host ""

# =========================================================
# REMOVER APPS UWP
# =========================================================

Write-Host "Removendo aplicativos..." -ForegroundColor Cyan
Write-Host ""

$apps = @(

    "*Xbox*",
    "*Gaming*",
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
    "*OfficeHub*",
    "*3DBuilder*",
    "*3DViewer*",
    "*MixedReality*",
    "*OneConnect*",
    "*FeedbackHub*",
    "*Wallet*",
    "*Alarms*",
    "*StickyNotes*",
    "*SoundRecorder*",
    "*YourPhone*",
    "*WindowsCommunicationsApps*",
    "*Paint3D*",
    "*Cortana*",
    "*Todos*",
    "*PowerAutomate*",
    "*News*",
    "*DevHome*"
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
# DESABILITAR SERVIÇOS
# =========================================================

Write-Host "Desabilitando serviços..." -ForegroundColor Cyan
Write-Host ""

$services = @(

    "SysMain",
    "WSearch",
    "DiagTrack",
    "dmwappushservice",
    "MapsBroker",
    "Fax",
    "RetailDemo",
    "RemoteRegistry",
    "lfsvc",
    "SEMgrSvc",
    "PcaSvc",
    "WerSvc",
    "wisvc",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "WMPNetworkSvc"
)

foreach ($svc in $services) {

    $serviceExists = Get-Service $svc -ErrorAction SilentlyContinue

    if ($serviceExists) {

        Write-Host "Desabilitando: $svc"

        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

Write-Host ""

# =========================================================
# DESABILITAR TAREFAS
# =========================================================

Write-Host "Desabilitando tarefas agendadas..." -ForegroundColor Cyan
Write-Host ""

Get-ScheduledTask |
Where-Object {

    $_.TaskName -like "*Telemetry*" -or
    $_.TaskName -like "*Customer Experience*" -or
    $_.TaskName -like "*CEIP*" -or
    $_.TaskName -like "*Application Experience*" -or
    $_.TaskName -like "*Office*" -or
    $_.TaskName -like "*Xbox*" -or
    $_.TaskName -like "*EdgeUpdate*"

} |
Disable-ScheduledTask -ErrorAction SilentlyContinue

Write-Host ""

# =========================================================
# DESABILITAR HIBERNAÇÃO
# =========================================================

Write-Host "Desabilitando hibernação..." -ForegroundColor Cyan

powercfg -h off

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
# REMOVER FEATURES OPCIONAIS
# =========================================================

Write-Host "Removendo recursos opcionais..." -ForegroundColor Cyan
Write-Host ""

$features = @(

    "Printing-XPSServices-Features",
    "WorkFolders-Client",
    "Internet-Explorer-Optional-amd64",
    "MicrosoftWindowsPowerShellV2"
)

foreach ($feature in $features) {

    Write-Host "Removendo feature: $feature"

    Disable-WindowsOptionalFeature `
    -Online `
    -FeatureName $feature `
    -Remove `
    -NoRestart `
    -ErrorAction SilentlyContinue
}

Write-Host ""

# =========================================================
# TELEMETRIA
# =========================================================

Write-Host "Desabilitando telemetria..." -ForegroundColor Cyan

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
/v AllowTelemetry `
/t REG_DWORD `
/d 0 `
/f | Out-Null

Write-Host ""

# =========================================================
# DESABILITAR CONSUMER EXPERIENCE
# =========================================================

Write-Host "Desabilitando Consumer Experience..." -ForegroundColor Cyan

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
/v DisableWindowsConsumerFeatures `
/t REG_DWORD `
/d 1 `
/f | Out-Null

Write-Host ""

# =========================================================
# DESABILITAR SUGESTÕES
# =========================================================

Write-Host "Desabilitando sugestões..." -ForegroundColor Cyan

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
# EFEITOS VISUAIS
# =========================================================

Write-Host "Desabilitando efeitos visuais..." -ForegroundColor Cyan

Set-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" `
-Name VisualFXSetting `
-Type DWord `
-Value 2 `
-ErrorAction SilentlyContinue

Write-Host ""

# =========================================================
# TRANSPARÊNCIA
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
# WINDOWS 11
# =========================================================

if ($IsWindows11) {

    Write-Host "Aplicando ajustes Windows 11..." -ForegroundColor Cyan
    Write-Host ""

    reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" `
    /v AllowNewsAndInterests `
    /t REG_DWORD `
    /d 0 `
    /f | Out-Null

    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" `
    /v TurnOffWindowsCopilot `
    /t REG_DWORD `
    /d 1 `
    /f | Out-Null
}

Write-Host ""

# =========================================================
# Remover Jogos, LinkedIn e Solitaire
# =========================================================

# Solitaire
Get-AppxPackage -AllUsers "*Solitaire*" |
Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

Get-AppxProvisionedPackage -Online |
Where-Object {$_.DisplayName -like "*Solitaire*"} |
Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue


# LinkedIn
Get-AppxPackage -AllUsers "*LinkedIn*" |
Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

Get-AppxProvisionedPackage -Online |
Where-Object {$_.DisplayName -like "*LinkedIn*"} |
Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue


# Xbox e jogos
$XboxApps = @(
    "*Xbox*",
    "*Gaming*",
    "*GameBar*"
)

foreach ($app in $XboxApps) {

    Get-AppxPackage -AllUsers $app |
    Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

    Get-AppxProvisionedPackage -Online |
    Where-Object {$_.DisplayName -like $app} |
    Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Remoção concluída." -ForegroundColor Green
Write-Host ""


# =========================================================
# LIMPEZA COMPONENT STORE
# =========================================================

Write-Host "Limpando componentes..." -ForegroundColor Cyan

Dism.exe /online /Cleanup-Image /StartComponentCleanup

Write-Host ""

# =========================================================
# LIMPEZA TEMP
# =========================================================

Write-Host "Limpando temporários..." -ForegroundColor Cyan

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

Write-Host "=========================================" -ForegroundColor Green
Write-Host " Otimização concluída"
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""

Write-Host "Reinicie o computador." -ForegroundColor Yellow
Write-Host ""

Pause
