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

$ErrorActionPreference = "SilentlyContinue"
$log = "C:\temp\hardening_reversao_completa.txt"

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERRO: EXECUTE COMO ADMINISTRADOR PRIMEIRO!" -ForegroundColor Red
    pause
    exit
}

if (!(Test-Path "C:\temp")) { New-Item "C:\temp" -ItemType Directory }

Clear-Host
Write-Host "REVERSAO DE HARDENING WINDOWS 10/11 - SELECIONE ITENS" -ForegroundColor Green

# Lista de itens disponíveis
$itens = 1..25
$itens | ForEach-Object { Write-Host "$_ - Item $_" }

# Pergunta quais itens desfazer (ex: 1,3,5,21-24)
$selection = Read-Host "Digite os numeros dos itens a desfazer (separados por virgula ou intervalos 1-3)"
$selecionados = @()
$selection -split ',' | ForEach-Object {
    if ($_ -match '-') {
        $range = $_ -split '-'
        $selecionados += $range[0]..$range[1]
    } else {
        $selecionados += [int]$_
    }
}
$selecionados = $selecionados | Sort-Object -Unique

# Funções de reversao
function ReverterFirewall {
    netsh advfirewall set allprofiles state off | Out-Null
    netsh advfirewall firewall delete rule name="SMBBlock445" | Out-Null
    "Firewall e SMB445 revertidos" | Out-File $log -Append
}

function ReverterNTLM { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 0 -Type DWord; "NTLM revertido" | Out-File $log -Append }
function ReverterWDigest { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -Type DWord; "WDigest revertido" | Out-File $log -Append }
function ReverterLLMNR { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1 -Type DWord; "LLMNR revertido" | Out-File $log -Append }
function ReverterRestrictAnonymous { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 0 -Type DWord; "RestrictAnonymous revertido" | Out-File $log -Append }
function ReverterLSASS { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Type DWord; "LSASS PPL revertido" | Out-File $log -Append }
function ReverterRDP { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord; "RDP revertido" | Out-File $log -Append }
function ReverterUAC { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord; "UAC revertido" | Out-File $log -Append }
function ReverterAutorun { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 91 -Type DWord; "Autorun revertido" | Out-File $log -Append }
function ReverterGuest { net user Guest /active:yes | Out-Null; "Conta Guest reativada" | Out-File $log -Append }
function ReverterAuditoria {
    auditpol /set /subcategory:"Logon" /success:disable /failure:disable | Out-Null
    auditpol /set /subcategory:"Logoff" /success:disable /failure:disable | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
    "Auditoria de logon/logoff/processo revertida" | Out-File $log -Append
}
function ReverterPSLogging {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (Test-Path $path) { Remove-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue }
    "PowerShell ScriptBlock Logging revertido" | Out-File $log -Append
}
function ReverterCmdlineLogging {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (Test-Path $path) { Remove-ItemProperty -Path $path -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue }
    "Cmdline Logging revertido" | Out-File $log -Append
}
function ReverterServico($servico) { 
    if (Get-Service $servico -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$servico" -Name "Start" -Value 2 -Type DWord
        "$servico revertido" | Out-File $log -Append
    }
}
function ReverterASR {
    $asrRules = @("D4F940AB-401B-4EFC-AADC-AD5F3C50688A","75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84","3B576869-A4EC-4529-8536-B80A7769E899")
    foreach ($rule in $asrRules) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $rule -ErrorAction SilentlyContinue }
    "ASR revertido" | Out-File $log -Append
}
function ReverterMOTW { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 0 -Type DWord; "MOTW revertido" | Out-File $log -Append }
function ReverterSmartScreen { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Enabled"; "SmartScreen revertido" | Out-File $log -Append }
function ReverterSRP {
    $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    if (Test-Path "$base\0\Paths") { Remove-Item "$base\0\Paths" -Recurse -Force }
    Remove-ItemProperty -Path $base -Name "DefaultLevel" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $base -Name "PolicyScope" -ErrorAction SilentlyContinue
    "SRP revertido" | Out-File $log -Append
}
function ReverterWindowsUpdate { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type DWord; "Windows Update revertido" | Out-File $log -Append }

# Mapeamento itens -> função
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
        13 { ReverterCmdlineLogging }
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
        25 { ReverterWindowsUpdate }
        default { "Item $item não possui reversão automatizada" | Out-File $log -Append }
    }
}

"=== REVERSAO COMPLETA CONCLUIDA $(Get-Date) ===" | Out-File $log -Append
Start-Process notepad $log
Write-Host "REVERSAO FINALIZADA. Confira log em $log" -ForegroundColor Green
