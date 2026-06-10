# ad-identity-audit-tracker
Automação em PowerShell para auditoria de identidades no Active Directory. Rastreia de forma precisa a autoria de alterações críticas e deleções de contas através do Event ID 4738 nos Domain Controllers.



# Active Directory Identity Audit: Tracker (Event ID 4738)

## 📌 Contexto de Negócio (IGA & Compliance)
Em processos de **Governança de Identidades (IGA)**, Auditoria e Resposta a Incidentes, a rastreabilidade completa das ações é um pilar indispensável. Este script foi desenvolvido para solucionar cenários onde uma conta de usuário crítica é desabilitada no domínio e o time de **Gestão de Acessos** precisa validar a origem da ação: se partiu de uma automação legítima do sistema de identidade, de uma alteração autorizada via Service Desk ou de uma falha operacional.

## ⚙️ Funcionalidades Técnicas
* **Varredura Multi-DC Dinâmica:** Localiza e interroga automaticamente todos os Controladores de Domínio (DCs) ativos na floresta do AD.
* **Parsing Estruturado em XML:** Converte logs brutos gerados pelo `Get-WinEvent` em árvores XML para extrair cirurgicamente quem executou a ação (`SubjectUserName`) e quem sofreu o impacto (`TargetUserName`).
* **Filtro de Segurança Antifalhas:** Focado especificamente no Event ID `4738`, mitigando falsos positivos e capturando apenas mudanças reais de status no controle de contas (UAC).

## 🛠️ Requisitos
* Módulo `ActiveDirectory` ativo na estação de execução.
* Privilégios de leitura nos Logs de Segurança (Security Event Log) dos Domain Controllers.
