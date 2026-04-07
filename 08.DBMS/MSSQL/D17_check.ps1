# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-17
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 하
# @Title       : AuditTable은데이터베이스관리자계정으로접근하도록제한
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-17"
$ITEM_NAME = "AuditTable은데이터베이스관리자계정으로접근하도록제한"
$SEVERITY = "하"
$CATEGORY = "2.접근제어"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'Audit Table 접근 권한을 관리자 계정으로 제한함으로써 비인가자가 감사 데이터의 수정, 삭제하는 것을 방지하고, 감사 기록 의무 결성과 신뢰성을 보장하기 위함'
$threat = 'Audit Table이 데이터베이스 관리자 계정에 속하지 않을 경우, 비인가자가 감사 데이터의 수정, 삭제 등을 수행할 수 있으므로 보안 사고 발생 시 원인 분석이 불가능하게 되며, 이로 인해 재발 방지를 위한 조치를 할 수 없으므로 동일 유형의 공격이 반복되거나 시스템 취약점의 악용이 반복될 위험이 존재함'
$criteria_good = 'AuditTable 접근 권한이 관리자 계정으로 설정한 경우'
$criteria_bad = 'AuditTable 접근 권한이 일반 계정으로 설정한 경우'
$remediation = 'AuditTable 접근 권한을 관리자 계정으로 제한'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
$resultDetails = @()

# SQL Server 모듈 로드
try {
    Import-Module SqlServer -ErrorAction SilentlyContinue
}
catch {
    # SqlServer 모듈이 없으면 sqlcmd 사용
}

# SQL Server 서비스 확인
$mssqlService = Get-Service | Where-Object { $_.Name -like '*SQL*' -and $_.Status -eq 'Running' } | Select-Object -First 1

if (-not $mssqlService) {
    $diagnosis_result = "GOOD"
    $status = "양호"
    $inspection_summary = "MSSQL 서비스 미실행"
    $command_result = "SQL Server service not found or not running"
    $commandExecuted = "Get-Service | Where-Object { `$_.Name -like '*SQL*' }"

    Save-DualResult -ItemId $ITEM_ID `
        -ItemName $ITEM_NAME `
        -Status $status `
        -FinalResult $diagnosis_result `
        -InspectionSummary $inspection_summary `
        -CommandResult $command_result `
        -CommandExecuted $commandExecuted `
        -GuidelinePurpose $purpose `
        -GuidelineThreat $threat `
        -GuidelineCriteriaGood $criteria_good `
        -GuidelineCriteriaBad $criteria_bad `
        -GuidelineRemediation $remediation `
        -ScriptDir $SCRIPT_DIR

    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($diagnosis_result)"
    exit 0
}

# SQL Server 연결
$serverName = $env:COMPUTERNAME
$connectionSuccess = $false

try {
    $testQuery = "SELECT 1"
    $result = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $testQuery -ErrorAction SilentlyContinue
    if ($result) {
        $connectionSuccess = $true
    }
}
catch {
    $connectionSuccess = $false
}

if ($connectionSuccess) {
    # SQL Server Audit 상태 확인
    try {
        $auditQuery = "SELECT name, is_state_enabled FROM sys.server_audits;"
        $auditResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $auditQuery -ErrorAction SilentlyContinue

        if ($auditResult) {
            foreach ($audit in $auditResult) {
                $state = if ($audit.is_state_enabled -eq 1) { "활성화" } else { "비활성화" }
                $resultDetails += "$($audit.name): $state"
            }
        }
    }
    catch {
        $resultDetails += "감사 상태 확인 실패: $($_.Exception.Message)"
    }
}

$inspection_summary = "MSSQL 감사 테이블 접근 권한 점검`r`n`r`n"
$inspection_summary += "이 항목은 Oracle AUD$ 테이블 전용 항목입니다. MSSQL은 SQL Server Audit 기능을 사용합니다.`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. 서버 감사(Server Audit) 확인:`r`n"
$inspection_summary += "   SELECT name, is_state_enabled FROM sys.server_audits;`r`n`r`n"
$inspection_summary += "2. 감사 로그 접근 권한 확인:`r`n"
$inspection_summary += "   SELECT server_principal_name, permission_name`r`n"
$inspection_summary += "   FROM sys.server_permissions`r`n"
$inspection_summary += "   WHERE class = 'SERVER' AND permission_name = 'CONTROL SERVER';`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. sysadmin 역할의 멤버만 감사 로그에 접근하도록 제한`r`n"
$inspection_summary += "2. CONTROL SERVER 권한을 최소한으로 부여`r`n"
$inspection_summary += "3. 감사 로그 파일 위치 보안 (NTFS 권한 설정)`r`n`r`n"
$inspection_summary += "검증 결과:`r`n"
$inspection_summary += ($resultDetails -join "`r`n")

$commandExecuted = "SELECT * FROM sys.dm_server_audit_status;"
$command_result = $resultDetails -join "`n"

$diagnosis_result = "MANUAL"
$status = "수동진단"

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $diagnosis_result `
    -InspectionSummary $inspection_summary `
    -CommandResult $command_result `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($diagnosis_result)"

exit 0
