<#
.SYNOPSIS
    Auditoria de Identidades: Rastreamento de Autoria em Contas Desabilitadas no AD.
    
.DESCRIPTION
    Este script varre os Controladores de Domínio (DCs) em busca do Event ID 4738 
    (User Account Management) no log de Segurança do Windows. O objetivo é identificar 
    com precisão a data, o servidor e a identidade (Subject) responsável por desabilitar 
    uma conta específica (Target).
#>

Import-Module ActiveDirectory

# --- CONFIGURAÇÃO DE ENTRADA (Alvo da Auditoria) ---
# Substitua pelo SamAccountName do usuário a ser auditado
$UsuarioAfetado = "usuario.exemplo"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   AUDITORIA DE IAM: QUEM DESABILITOU A CONTA?            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "`nBuscando Controladores de Domínio ativos..." -ForegroundColor White

try {
    $DCs = (Get-ADDomainController -Filter *).Name
    Write-Host "Foram encontrados $($DCs.Count) servidores para varredura." -ForegroundColor Gray
} catch {
    Write-Host "[ERRO CRÍTICO] Falha ao listar os Controladores de Domínio: $($_.Exception.Message)" -ForegroundColor Red
    break
}

# Coleção para armazenar os resultados consolidados
$ResultadosAuditoria = @()

foreach ($DC in $DCs) {
    Write-Host "`nVarrendo registros de alteração no servidor: $DC..." -ForegroundColor Cyan
    try {
        # Busca o evento 4738 (Um objeto de usuário foi alterado)
        $Eventos = Get-WinEvent -ComputerName $DC -FilterHashtable @{LogName='Security'; Id=4738} -ErrorAction SilentlyContinue | 
                   Where-Object { $_.Message -like "*Target Account:*$UsuarioAfetado*" }

        foreach ($E in $Eventos) {
            # Converte o evento bruto em XML para parsing preciso das propriedades estruturadas
            $xml = [xml]$E.ToXml()
            
            # Valida se a alteração ENVOLVE desativação de conta (Account Disabled ou modificações de UAC)
            if ($E.Message -like "*Account Disabled*" -or $E.Message -like "*'Don't Expire Password' - Enabled*") {
                
                # Extração segura dos nós de dados do XML
                $SubjectUser = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" } | Select-Object -ExpandProperty "#text"
                $TargetUser  = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }  | Select-Object -ExpandProperty "#text"

                $ResultadosAuditoria += [pscustomobject]@{
                    DataAlteracao   = $E.TimeCreated
                    ServidorAuditado = $E.MachineName
                    ResponsavelAction = $SubjectUser
                    UsuarioImpactado  = $TargetUser
                }
            }
        }
    } catch {
        Write-Host "  [AVISO] Servidor $DC temporariamente inacessível para leitura de logs." -ForegroundColor Yellow
    }
}

# --- EXIBIÇÃO DOS RESULTADOS ---
if ($ResultadosAuditoria.Count -gt 0) {
    Write-Host "`n=================== EVENTOS ENCONTRADOS ===================" -ForegroundColor Green
    $ResultadosAuditoria | Out-String | Write-Host -ForegroundColor White
} else {
    Write-Host "`n[INFO] Nenhum evento de desativação recente encontrado para o usuário: $UsuarioAfetado" -ForegroundColor Yellow
}
