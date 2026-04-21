####################################################################################################
# SCRIPT DE REVERSAO COMPLETA SELECIONAVEL - HARDENING WINDOWS 10/11 - 25 ITENS  
# Autor: Diego Costa (@diegocostaroot) / Projeto Root (youtube.com/projetoroot)
# Veja o link: https://wiki.projetoroot.com.br
# 2026
# 
# Executar o Powershell como Administrador
# Entrar na pasta que fez o download e executar .\unhardening-windows-desktop.ps1
# Após a execução é extremamente necessário reiniciar, 
# teste tudo que for possivel antes de liberar o acesso.
# 
# Testado em: Windows 10 22H2+, Windows 11, Windows Server 2016+
# TODAS as ações são registradas em um relatório em C:\temp\hardening_completo.txt
#
# Objetivo: Remover itens de Hardening aplicados através do script hardening-windows-desktop.ps1  
# em: https://github.com/projetoroot/hardening-windows-desktop
# Para reverter digite os numeros dos itens a desfazer (separados por virgula ou intervalos 1-3)
####################################################################################################

###############################################################################
# REVERSAO PERSONALIZADA - HARDENING WINDOWS
###############################################################################

$ErrorActionPreference = "SilentlyContinue"
$log = "C:\temp\hardening_reversao.txt"

# Verifica admin
if (-not ([Security.Principal.WindowsPrincipal] `
[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "EXECUTE COMO ADMINISTRADOR" -ForegroundColor Red
    pause
    exit
}

# Cria pasta/log
if (!(Test-Path "C:\temp")) { New-Item "C:\temp" -ItemType Directory | Out-Null }
"==== INICIO REVERSAO $(Get-Date) ====" | Out-File $log

Clear-Host

# =========================
# MENU
# =========================
$menu = @{
1  = "Firewall + SMB"
2  = "NTLM"
3  = "WDigest"
4  = "LLMNR"
5  = "RestrictAnonymous"
6  = "LSASS PPL"
7  = "RDP"
8  = "UAC"
9  = "Autorun"
10 = "Guest"
11 = "Auditoria"
12 = "PowerShell Logging"
13 = "CmdLine Logging"
14 = "RemoteRegistry"
15 = "WebClient"
16 = "PrintSpooler"
17 = "LanmanServer"
18 = "Windows Search"
19 = "BITS"
20 = "Telnet"
21 = "ASR"
22 = "MOTW"
23 = "SmartScreen"
24 = "SRP"
25 = "Windows Update"
}

Write-Host "==== ITENS DISPONIVEIS ====" -ForegroundColor Cyan
$menu.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Write-Host "$($_.Key) - $($_.Value)"
}

Write-Host ""
Write-Host "Digite: 1-5,8,10 ou ALL" -ForegroundColor Yellow
$inputUser = Read-Host "Selecao"

# =========================
# PROCESSAMENTO
# =========================
$selecionados = @()

if ($inputUser.ToUpper() -eq "ALL") {
    $selecionados = $menu.Keys
} else {
    $inputUser -split ',' | ForEach-Object {
        if ($_ -match '-') {
            $r = $_ -split '-'
            $selecionados += ($r[0]..$r[1])
        } elseif ($_ -match '^\d+$') {
            $selecionados += [int]$_
        }
    }
}

$selecionados = $selecionados | Sort-Object -Unique

# =========================
# LOG
# =========================
function Log($msg) {
    "$((Get-Date)) - $msg" | Out-File $log -Append
}

# =========================
# FUNCOES
# =========================

function ReverterFirewall {
    netsh advfirewall set allprofiles state off | Out-Null
    netsh advfirewall firewall delete rule name="SMBBlock445" | Out-Null
    Log "Firewall revertido"
}

function ReverterNTLM {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 3
    Log "NTLM ajustado para padrão"
}

function ReverterWDigest {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 1
    Log "WDigest revertido"
}

function ReverterLLMNR {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 1
    Log "LLMNR ativo"
}

function ReverterRestrictAnonymous {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 0
    Log "RestrictAnonymous revertido"
}

function ReverterLSASS {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 0
    Log "LSASS PPL desativado"
}

function ReverterRDP {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0
    Log "RDP liberado"
}

function ReverterUAC {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 5
    Log "UAC padrão restaurado"
}

function ReverterAutorun {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 91
    Log "Autorun padrão restaurado"
}

function ReverterGuest {
    $guest = Get-LocalUser | Where-Object { $_.SID -like "*-501" }

    if ($guest) {
        Enable-LocalUser -Name $guest.Name
        Log "Guest ativado ($($guest.Name))"
    } else {
        Log "Conta Guest não encontrada"
    }
}

function ReverterAuditoria {

    $subcats = auditpol /list /subcategory
    if ($subcats -match "Logon") {
        auditpol /set /subcategory:"Logon" /success:disable /failure:disable | Out-Null
    }
    if ($subcats -match "Logoff") {
        auditpol /set /subcategory:"Logoff" /success:disable /failure:disable | Out-Null
    }
    if ($subcats -match "Process Creation") {
        auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
    }
    Log "Auditoria desativada (auto-detect)"
}

function ReverterPSLogging {
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging") {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    }
    Log "PS Logging removido"
}

function ReverterCmdline {
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit") {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    }
    Log "CmdLine logging removido"
}

function ReverterServico($nome) {
    if (Get-Service $nome -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$nome" `
        -Name "Start" -Value 3
        Log "$nome ajustado para manual"
    }
}

function ReverterASR {
    $rules = @(
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
    "3B576869-A4EC-4529-8536-B80A7769E899",
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
    )
    foreach ($r in $rules) {
        Remove-MpPreference -AttackSurfaceReductionRules_Ids $r -ErrorAction SilentlyContinue
    }
    Log "ASR revertido"
}

function ReverterMOTW {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
    -Name "SaveZoneInformation" -Value 2
    Log "MOTW padrão restaurado"
}

function ReverterSmartScreen {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
    -Name "SmartScreenEnabled" -Value "Warn"
    Log "SmartScreen padrão restaurado"
}

function ReverterSRP {
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer") {
        Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer" -Recurse -Force
    }
    Log "SRP removido"
}

function ReverterWU {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoUpdate" -Value 0
    Log "Windows Update automático reativado"
}

# =========================
# EXECUCAO
# =========================
foreach ($item in $selecionados) {

    Write-Host "Revertendo: $($menu[$item])"

    switch ($item) {
        1 { ReverterFirewall }
        2 { ReverterNTLM }
        3 { ReverterWDigest }
        4 { ReverterLLMNR }
        5 { ReverterRestrictAnonymous }
        6 { ReverterLSASS }
        7 { ReverterRDP }
        8 { ReverterUAC }
        9 { ReverterAutorun }
        10 { ReverterGuest }
        11 { ReverterAuditoria }
        12 { ReverterPSLogging }
        13 { ReverterCmdline }
        14 { ReverterServico "RemoteRegistry" }
        15 { ReverterServico "WebClient" }
        16 { ReverterServico "Spooler" }
        17 { ReverterServico "LanmanServer" }
        18 { ReverterServico "WSearch" }
        19 { ReverterServico "BITS" }
        20 { ReverterServico "TlntSvr" }
        21 { ReverterASR }
        22 { ReverterMOTW }
        23 { ReverterSmartScreen }
        24 { ReverterSRP }
        25 { ReverterWU }
    }
}

Log "==== FIM REVERSAO ===="

notepad $log
Write-Host "Concluido. Log em $log" -ForegroundColor Green
