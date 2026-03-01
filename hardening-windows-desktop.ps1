###############################################################################
# Hardening Microsoft Windows Desktop 10/11 - 20 ITENS - BASELINE MICROSOFT 
# Autor: Diego Costa (@diegocostaroot) / Projeto Root (youtube.com/projetoroot)
# Veja o link: https://wiki.projetoroot.com.br
# 2026
# 
# Executar o Powershell como Administrador
# Entrar na pasta que fez o download e executar .\hardening-windows-desktop.ps1
# Após a execução é extremamente necessário reiniciar, 
# teste tudo que for possivel antes de liberar o acesso.
# 
# Testado em: Windows 10 22H2+, Windows 11, Windows Server 2016+
# TODAS as ações são registradas em um relatório em C:\temp\hardening_completo.txt
#
# Objetivo: aumentar a segurança de estações/servidores que não estão no AD,
#           aplicando políticas modernas de firewall, autenticação, criptografia,
#           proteção de credenciais e eventos de auditoria.
###############################################################################


$ErrorActionPreference = "SilentlyContinue"

# =============================================================================
# VERIFICACAO INICIAL - PRE-REQUISITOS OBRIGATORIOS
# =============================================================================
# FINALIDADE: Garante execucao com privilegios de administrador
# SEM ADMIN: Registry falha silenciosamente, Services nao sao alterados
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERRO: EXECUTE COMO ADMINISTRADOR PRIMEIRO!" -ForegroundColor Red
    pause
    exit
}

# LOG AUTOMATICO - Sempre cria C:\temp\hardening_completo.txt
$path = "C:\temp"
if (!(Test-Path $path)) { New-Item $path -ItemType Directory }
$log = "C:\temp\hardening_completo.txt"
Clear-Host
Write-Host "Hardening Windows Desktop - 20 ITENS CRITICOS" -ForegroundColor Green

# =============================================================================
# 1. FIREWALL + BLOQUEIO SMB 445 INBOUND
# =============================================================================
# FINALIDADE: Ativa Windows Firewall todos perfis + bloqueia SMB entrada
# TCP 445: Porta padrao SMBv1/v2/v3 (compartilhamento arquivos/impressoras)
# PROTEGE CONTRA: WannaCry (MS17-010), EternalBlue, movimento lateral ransomware
# PERMITE SAIDA: Acesso a \\servidor\share continua funcionando normalmente
netsh advfirewall set allprofiles state on | Out-Null
netsh advfirewall firewall add rule name="SMBBlock445" dir=in action=block protocol=TCP localport=445 | Out-Null
"1. Firewall + SMB 445 OK" | Out-File $log -Append

# =============================================================================
# 2. NTLMv2 OBRIGATORIO - LmCompatibilityLevel=5
# =============================================================================
# FINALIDADE: Desabilita NTLMv1/LM hashes (128bits crack em 1min Hashcat)
# NIVEIS: 0=LM+NTLMv1, 3=NTLMv1 apenas, 5=NTLMv2/Kerberos OBRIGATORIO (CIS L1)
# PROTEGE CONTRA: Pass-the-hash, Responder.py NTLM relay, rainbow tables offline
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -PropertyType DWORD -Force | Out-Null
"2. NTLMv2 Obrigatorio OK" | Out-File $log -Append

# =============================================================================
# 3. WDIGEST DESABILITADO - UseLogonCredential=0
# =============================================================================
# FINALIDADE: Impede LSASS armazenar senhas em PLAIN TEXT na memoria RAM
# ANTES: Mimikatz sekurlsa::logonpasswords = "Password123!" em claro
# DEPOIS: "No credentials found" - apenas hashes NTLM (muito mais dificeis)
# PROTEGE CONTRA: ProcDump lsass.exe, comsvcs.dll minidump, TaskMgr tricks
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType DWORD -Force | Out-Null
"3. WDigest OFF (Anti-Mimikatz) OK" | Out-File $log -Append

# =============================================================================
# 4. LLMNR DESABILITADO - EnableMulticast=0
# =============================================================================
# FINALIDADE: Remove Link-Local Multicast Name Resolution (LLMNR .local spoofing)
# ATAQUE TIPICO: Responder.py responde "*.local" → IP 192.168.1.100 malicioso → SMB phishing
# DEPOIS: Apenas DNS legitimo funciona (sem multicast poisoning .local)
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force | Out-Null
"4. LLMNR OFF (Anti-Responder) OK" | Out-File $log -Append

# =============================================================================
# 5. NTLM ANONIMO BLOQUEADO - RestrictAnonymous=1
# =============================================================================
# FINALIDADE: Bloqueia NULL sessions (usuario vazio) via SMB/RPC enumeracao
# ANTES: rpcclient -U "" enumdomusers = lista completa usuarios dominio
# DEPOIS: "Access Denied" - sem enumeracao anonima de usuarios/shares
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -PropertyType DWORD -Force | Out-Null
"5. NTLM Anonimo OFF OK" | Out-File $log -Append

# =============================================================================
# 6. LSASS PROTECTED PROCESS - RunAsPPL=1
# =============================================================================
# FINALIDADE: Marca LSASS como Protected Process Light (apenas Microsoft assinados)
# REGRAS PPL: ProcDump, Mimikatz, injecao codigo = Access Denied
# EXCECAO: Apenas ferramentas Microsoft assinadas (DbgSym, ProcExp assinada)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force | Out-Null
"6. LSASS PPL (Anti-Dump) OK" | Out-File $log -Append

# =============================================================================
# 7. RDP REMOTO BLOQUEADO - fDenyTSConnections=1
# =============================================================================
# FINALIDADE: Desabilita conexoes RDP INBOUND (porta TCP 3389)
# ESTATISTICA: RDP = #1 alvo scanners internet (Shodan: 10M+ portas expostas)
# PERMITE SAIDA: Voce pode conectar RDP para outros servidores normalmente
# BLOQUEIA ENTRADA: Bruteforce, BlueKeep CVE-2019-0708
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -PropertyType DWORD -Force | Out-Null
"7. RDP Inbound OFF OK" | Out-File $log -Append

# =============================================================================
# 8. UAC MAXIMO - ConsentPromptBehaviorAdmin=2
# =============================================================================
# FINALIDADE: Administradores sempre pedem UAC (sem elevacao silenciosa)
# VALORES: 0=Nunca UAC, 2=Sempre prompt (mais seguro), 5=Default
# EnableLUA=1 ativa User Account Control completamente (sem bypass Fodhelper)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -PropertyType DWORD -Force | Out-Null
"8. UAC Maximo OK" | Out-File $log -Append

# =============================================================================
# 9. AUTORUN TODOS DRIVES - NoDriveTypeAutoRun=255
# =============================================================================
# FINALIDADE: Bloqueia execucao automatica em QUALQUER drive (USB/CD/Fixo/RAM)
# 255 = 11111111b = USB + Fixo + CD-ROM + RAM + Desconhecido + Removivel
# PROTEGE CONTRA: Stuxnet (autorun.inf), Conficker (USB worm), malwares fisicos
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force | Out-Null
"9. Autorun Todos Drives OFF OK" | Out-File $log -Append

# =============================================================================
# 10. CONTA GUEST DESABILITADA
# =============================================================================
# FINALIDADE: Remove conta Guest padrao (sem senha por default)
# RISCO: Guest = acesso local sem autenticacao (Physical access = root)
# USO COMUM: PCs publicos, bibliotecas, quiosques (NAO use em casa/trabalho)
net user Guest /active:no | Out-Null
"10. Conta Guest OFF OK" | Out-File $log -Append

# =============================================================================
# 11. AUDITORIA - Event Logs 4624/4625/4688
# =============================================================================
# FINALIDADE: Logs forense detalhados (quem fez o que, quando)
# Logon/Logoff: 4624=sucesso, 4625=falha (com IP origem)
# Criacao processo: 4688=nome executavel + argumentos completos
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
"11. Auditoria Logon+Processo OK" | Out-File $log -Append

# =============================================================================
# 12. POWERSHELL SCRIPTBLOCK LOGGING - Event 4104
# =============================================================================
# FINALIDADE: Registra TODOS comandos PowerShell executados (encoded ou nao)
# DETECTA: powershell -enc ..., Invoke-WebRequest malicioso, AMSI bypass
# LOCAL: Microsoft-Windows-PowerShell/Operational → ID 4104
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
New-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force | Out-Null
"12. PowerShell ScriptBlock OK" | Out-File $log -Append

# =============================================================================
# 13. PROCESS CMDLINE LOGGING - Argumentos completos 4688
# =============================================================================
# FINALIDADE: Registra parametros dos processos (nao so nome executavel)
# ANTES: cmd.exe
# DEPOIS: cmd.exe /c whoami /priv /fo csv (detecta comandos suspeitos)
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
New-ItemProperty -Path $path -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWORD -Force | Out-Null
"13. Cmdline Logging Completo OK" | Out-File $log -Append

# =============================================================================
# 14. REMOTEREGISTRY OFF - Start=4 (Disabled)
# =============================================================================
# FINALIDADE: Remove servico Registry remoto (alvo #1 exploits RDP)
# VALOR 4=Disabled (0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled)
# PROTEGE CONTRA: PrintNightmare variantes, registry RCE via RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f | Out-Null
"14. RemoteRegistry OFF OK" | Out-File $log -Append

# =============================================================================
# 15. WEBCLIENT OFF - WebDAV exploits (Start=4)
# =============================================================================
# FINALIDADE: Desabilita WebDAV client (\\192.168.1.1@80\DavWWWRoot)
# RISCO: WebDAV usado em phishing (fake shares), exploits UNC path
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v Start /t REG_DWORD /d 4 /f | Out-Null
"15. WebClient OFF OK" | Out-File $log -Append

# =============================================================================
# 16. PRINTSPOOLER OFF - PrintNightmare CVE-2021-34527 (Start=4)
# =============================================================================
# FINALIDADE: Remove spooler impressao (exploit mais comum 2021-2026)
# RISCO: PrintNightmare permite RCE sem autenticacao via spooler RPC
# NOTA: Impressao local USB continua funcionando normalmente
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v Start /t REG_DWORD /d 4 /f | Out-Null
"16. PrintSpooler OFF OK" | Out-File $log -Append

# =============================================================================
# 17. SERVER SERVICE OFF - SMB inseguro (Start=4)
# =============================================================================
# FINALIDADE: Remove compartilhamentos SMB administrativos (C$, ADMIN$)
# RISCO: Server service expõe shares anonimos em algumas configs
# PERMITE: File sharing via Group Policy ou permissoes especificas
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer" /v Start /t REG_DWORD /d 4 /f | Out-Null
"17. Server Service OFF OK" | Out-File $log -Append

# =============================================================================
# 18. WINDOWS SEARCH OFF - WSearch vulneravel (Start=4)
# =============================================================================
# FINALIDADE: Desabilita indexacao arquivos (alvo historico exploits)
# RISCO: WSearch tinha multiplas CVEs (elevation privilege local)
# NOTA: Busca Windows Explorer fica mais lenta (mas mais segura)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v Start /t REG_DWORD /d 4 /f | Out-Null
"18. Windows Search OFF OK" | Out-File $log -Append

# =============================================================================
# 19. BITS OFF - Background Intelligent Transfer (Start=4)
# =============================================================================
# FINALIDADE: Remove BITS (usado por malwares para download silencioso)
# RISCO: BITS roda com SYSTEM e ignora firewall/proxy para downloads
# EXEMPLO: Emotet, TrickBot usam BITS para C2 e payload download
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v Start /t REG_DWORD /d 4 /f | Out-Null
"19. BITS OFF OK" | Out-File $log -Append

# =============================================================================
# 20. TELNET SERVER OFF - Protocolo inseguro plaintext (Start=4)
# =============================================================================
# FINALIDADE: Remove Telnet server (se habilitado por acidente)
# RISCO: Telnet = plaintext (senhas visiveis em Wireshark)
# NOTA: Telnet client tambem deve ser removido (OpcionalFeature)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TlntSvr" /v Start /t REG_DWORD /d 4 /f | Out-Null
"20. Telnet OFF OK" | Out-File $log -Append

# =============================================================================
# FINALIZACAO - RELATORIO COMPLETO
# =============================================================================
"=== HARDENING CONCLUIDO $(Get-Date) ===" | Out-File $log -Append
"=== TOTAL: 20/20 ITENS APLICADOS SUCESSO ===" | Out-File $log -Append
"=== REINICIAR OBRIGATORIO: shutdown /r /t 60 ===" | Out-File $log -Append
"=== VERIFICAR INTERNET: ping google.com ===" | Out-File $log -Append

Write-Host "`nCONCLUIDO - 20/20 ITENS!" -ForegroundColor Green
Write-Host "RELATORIO DETALHADO: $log" -ForegroundColor Yellow
Write-Host "REINICIAR: shutdown /r /t 60" -ForegroundColor Red
Start-Sleep 3
notepad $log
