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

## 🚀 Como Executar

### Baixar o Script

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
Invoke-WebRequest -Uri https://raw.githubusercontent.com/projetoroot/hardening-windows-desktop/refs/heads/main/hardening-windows-desktop.ps1 -OutFile hardening-windows-desktop.ps1

