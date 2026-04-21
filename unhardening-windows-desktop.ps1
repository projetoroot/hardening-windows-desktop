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
if (-NOT ([Security.Principal.WindowsPrincipal] 
[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
[Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "EXECUTE COMO ADMINISTRADOR" -ForegroundColor Red
    pause
    exit
}

# Cria pasta/log
if (!(Test-Path "C:\temp")) { New-Item "C:\temp" -ItemType Directory }
"==== INICIO REVERSAO $(Get-Date) ====" | Out-File $log

Clear-Host

# =========================
# LISTA DE ITENS
# =========================
$menu = @{
1  = "Firewall + Bloqueio SMB 445"
2  = "NTLMv2 Obrigatorio"
3  = "WDigest"
4  = "LLMNR"
5  = "RestrictAnonymous"
6  = "LSASS PPL"
7  = "RDP Bloqueado"
8  = "UAC Maximo"
9  = "Autorun"
10 = "Conta Guest"
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
21 = "ASR Defender"
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
Write-Host "Digite exemplo: 1-5,8,10,23 ou ALL" -ForegroundColor Yellow

$inputUser = Read-Host "Selecao"

# =========================
# PROCESSAMENTO DA ENTRADA
# =========================
$selecionados = @()

if ($inputUser -eq "ALL") {
    $selecionados = $menu.Keys
} else {
    $inputUser -split ',' | ForEach-Object {
        if ($_ -match '-') {
            $range = $_ -split '-'
            $selecionados += ($range[0]..$range[1])
        } else {
            if ($_ -match '^\d+$') {
                $selecionados += [int]$_
            }
        }
    }
}

$selecionados = $selecionados | Sort-Object -Unique

# =========================
# FUNCOES
# =========================

function Log($msg) {
    "$((Get-Date)) - $msg" | Out-File $log -Append
}

function ReverterFirewall {
    netsh advfirewall set allprofiles state off
    netsh advfirewall firewall delete rule name="SMBBlock445"
    Log "Firewall revertido"
}

function ReverterNTLM { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 0; Log "NTLM revertido" }
function ReverterWDigest { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1; Log "WDigest revertido" }
function ReverterLLMNR { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1; Log "LLMNR revertido" }
function ReverterRestrictAnonymous { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 0; Log "RestrictAnonymous revertido" }
function ReverterLSASS { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0; Log "LSASS revertido" }
function ReverterRDP { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0; Log "RDP liberado" }
function ReverterUAC { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5; Log "UAC revertido" }
function ReverterAutorun { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 91; Log "Autorun revertido" }
function ReverterGuest { net user Guest /active:yes; Log "Guest ativado" }

function ReverterAuditoria {
    auditpol /set /subcategory:"Logon" /success:disable /failure:disable
    auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
    Log "Auditoria revertida"
}

function ReverterPSLogging {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
    Log "PS Logging revertido"
}

function ReverterCmdline {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"
    Log "CmdLine revertido"
}

function ReverterServico($nome) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$nome" -Name "Start" -Value 2
    Log "$nome revertido"
}

function ReverterASR {
    Remove-MpPreference -AttackSurfaceReductionRules_Ids *
    Log "ASR revertido"
}

function ReverterMOTW {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 0
    Log "MOTW revertido"
}

function ReverterSmartScreen {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Enabled"
    Log "SmartScreen revertido"
}

function ReverterSRP {
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Recurse -Force
    Log "SRP removido"
}

function ReverterWU {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1
    Log "Windows Update revertido"
}

# =========================
# EXECUCAO
# =========================

foreach ($item in $selecionados) {

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
