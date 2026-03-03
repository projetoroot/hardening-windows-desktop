![CIS Compliance](https://img.shields.io/badge/CIS_Level_1-Hardened_100%25-brightgreen)

# 🛡️ Hardening Windows Desktop

Script em PowerShell para aplicação de hardening em Windows 10 e Windows 11, com foco em ambientes corporativos que não utilizam Active Directory como base para GPO.

O projeto aplica configurações locais de segurança inspiradas nas recomendações do CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0, traduzindo controles formais em execução prática e padronizada.

---

## 🎯 Objetivo do Projeto

Este script foi criado para:

- Aplicar baseline de segurança em estações Windows
- Reduzir a superfície de ataque do sistema operacional
- Endurecer autenticação e políticas locais
- Substituir parcialmente a ausência de GPO centralizadas
- Padronizar configurações de segurança em ambientes standalone

Ele não depende de domínio, AD ou infraestrutura corporativa avançada.

---

## 🏢 Cenários de Uso

Indicado para:

- Empresas pequenas e médias sem AD
- Ambientes em workgroup
- Máquinas administrativas
- Laboratórios técnicos
- Equipamentos expostos à internet
- Ambientes que precisam de padronização rápida

---

## 🔐 O Que o Script Aplica

### 1️⃣ Contas e Autenticação

- Desativação da conta Guest
- Endurecimento de políticas de senha
- Ajustes em NTLM
- Restrições de autenticação insegura

Previne:
- Enumeração de contas
- Uso indevido de credenciais locais
- Ataques de força bruta
- Uso de protocolos antigos

---

### 2️⃣ UAC e Elevação de Privilégio

- Força consentimento para elevação
- Impede elevação silenciosa
- Ajusta comportamento de contas administrativas

Previne:
- Escalonamento de privilégio
- Execução automática de malware
- Bypass de controles administrativos

---

### 3️⃣ Rede e Protocolos

- Desativação do SMBv1
- Ajustes em protocolos legados
- Endurecimento de configurações de rede

Previne:
- Exploração via protocolos obsoletos
- Ataques laterais em rede interna
- Vulnerabilidades conhecidas de SMB antigo

---

### 4️⃣ Serviços do Sistema

- Desativa serviços desnecessários
- Ajusta inicialização de serviços sensíveis
- Reduz exposição de componentes pouco usados

Previne:
- Movimentação lateral
- Execução remota de código
- Superfície de ataque desnecessária

---

### 5️⃣ Auditoria e Logs

- Ativa auditoria de eventos críticos
- Ajusta políticas de rastreamento
- Melhora visibilidade de atividades administrativas

Previne:
- Falta de rastreabilidade
- Dificuldade em investigação de incidentes
- Ausência de evidência em auditorias

---

### 6️⃣ Registro e Políticas Locais

- Aplica chaves equivalentes a GPO
- Endurece políticas locais via Registro
- Ajusta configurações sensíveis do sistema

Previne:
- Uso indevido de recursos do Windows
- Exploração de configurações padrão inseguras

---

## ⚙️ Requisitos

- Windows 10 ou Windows 11
- PowerShell 5.1 ou superior
- Execução como Administrador

---
## 📊 Controles Implementados com Criticidade e Peso

| Área            | Controle CIS        | Descrição                                              | Criticidade | Implementado | Peso |
|-----------------|--------------------|------------------------------------------------------|------------|--------------|------|
| Firewall        | 9.x                | Firewall ativo + Bloqueio TCP 445 (SMB Inbound)     | Alta       | Sim          | 10   |
| NTLM            | 2.3.10.x           | NTLMv2 obrigatório (LmCompatibilityLevel=5)         | Alta       | Sim          | 10   |
| Credenciais     | 18.8.x             | WDigest desabilitado                                 | Alta       | Sim          | 9    |
| DNS Client      | 18.6.x             | LLMNR desabilitado                                   | Alta       | Sim          | 8    |
| SMB             | 2.3.7.x            | Restrict Anonymous = 1                               | Alta       | Sim          | 8    |
| LSA             | 18.8.21.5          | LSASS como Protected Process                         | Alta       | Sim          | 10   |
| RDP             | 18.9.59.x          | Desabilitar RDP Inbound                              | Alta       | Sim          | 9    |
| UAC             | 2.3.17.x           | UAC nível máximo                                     | Média      | Sim          | 6    |
| AutoPlay        | 18.9.8.x           | Desativar Autorun em todos os drives                 | Média      | Sim          | 6    |
| Contas Locais   | 2.3.1.5            | Conta Guest desabilitada                             | Média      | Sim          | 5    |
| Auditoria       | 17.3.1             | Auditoria de Logon                                   | Média      | Sim          | 5    |
| Auditoria       | 17.6.1             | Auditoria de Criação de Processo                     | Média      | Sim          | 5    |
| PowerShell      | 18.10.7.x          | Script Block Logging                                 | Alta       | Sim          | 8    |
| Auditoria       | 17.6.x             | Log de linha de comando 4688                         | Alta       | Sim          | 8    |
| Serviços        | 18.9.x             | RemoteRegistry desabilitado                          | Média      | Sim          | 5    |
| Serviços        | 18.9.x             | WebClient desabilitado                               | Média      | Sim          | 5    |
| Serviços        | 18.9.x             | Print Spooler desabilitado                           | Alta       | Sim          | 9    |
| Serviços        | 18.9.x             | LanmanServer desabilitado                            | Alta       | Sim          | 9    |
| Serviços        | 18.9.x             | Windows Search desabilitado                          | Baixa      | Sim          | 3    |
| Serviços        | 18.9.x             | BITS desabilitado                                    | Média      | Sim          | 6    |
| Serviços        | 18.9.x             | Telnet Server desabilitado                           | Alta       | Sim          | 9    |

---

### 🎯 Score Máximo: 143 pontos

Score (%) = (Soma dos Controles Conformes / 143) x 100
Resultado = 100%

### Classificação

| Percentual | Nível |
|------------|-------|
| 90% - 100% | Hardened |
| 75% - 89%  | Good Baseline |
| 50% - 74%  | Moderate |
| < 50%      | Weak |

---

# 📌 Considerações Técnicas

- Alguns serviços desativados podem impactar ambientes corporativos.
- RDP off impede acesso remoto direto.
- LanmanServer off remove compartilhamentos administrativos.
- Print Spooler off impede impressão local e remota.
- BITS off pode impactar Windows Update.

Avaliar impacto antes de aplicar em produção.

---

# 🚀 Resultado Esperado

Aplicando os 25 controles:

- Redução relevante da superfície de ataque
- Maior proteção contra roubo de credenciais
- Menor exposição de serviços críticos
- Melhor capacidade de auditoria
- Padrão mínimo de segurança alinhado ao CIS

Este manual permite auditoria técnica e pontuação objetiva do nível de hardening aplicado.


## 🚀 Como Executar

### Copie o trecho abaixo e execute no Powershell como administrador

```powershell
cd $env:USERPROFILE\Downloads
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Invoke-WebRequest -Uri https://raw.githubusercontent.com/projetoroot/hardening-windows-desktop/refs/heads/main/hardening-windows-desktop.ps1 -OutFile hardening-windows-desktop.ps1
.\hardening-windows-desktop.ps1

