# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : DBMS 감사 로깅 점검
# @Description : 보안 감사 로그 기록 및 관리를 통한 추적성 확보
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-26"
$ITEM_NAME = "DBMS 감사 로깅 점검"
$SEVERITY = "상"
$CATEGORY = "4.패치관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '데이터, 로그, 응용 프로그램에 대한 감사 기록 정책을 수립하고 적용하여 데이터베이스에 문제 발생 시 원활하게 대응하기 위함'
$threat = '감사 기록 정책이 설정되어 있지 않을 경우, 데이터베이스에 문제 발생 시 원인을 규명할 수 있는 자료가 존재하지 않아 이에 대한 대처 및 개선 방안 수립이 어려워 장기적으로 심각한 보안 위험이 존재함'
$criteria_good = 'DBMS의 감사로 그저 장 정책이 수립되어 있으며, 정책 설정이 적용된 경우'
$criteria_bad = 'DBMS에 대한 감사로 그 저장을 하지 않거나, 정책 설정이 적용되지 않은 경우'
$remediation = 'DBMS에 대한 감사로 그저 장 정책 수립, 적용'

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
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
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
    # 감사 상태 확인
    try {
        $auditQuery = "SELECT name, is_state_enabled FROM sys.server_audits;"
        $auditResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $auditQuery -ErrorAction SilentlyContinue

        if ($auditResult) {
            foreach ($audit in $auditResult) {
                $state = if ($audit.is_state_enabled -eq 1) { "활성화" } else { "비활성화" }
                $resultDetails += "서버 감사: $($audit.name) - $state"
            }

            $enabledAudits = @($auditResult | Where-Object { $_.is_state_enabled -eq 1 })
            if ($enabledAudits.Count -gt 0) {
                $resultDetails += "감사 활성화됨: $($enabledAudits.Count)개 (양호)"
            } else {
                $resultDetails += "감사 비활성화됨 (취약)"
            }
        }

        # Error Log 확인
        $errorLogQuery = "EXEC xp_readerrorlog 0, 1, NULL, NULL, '2026-01-01', NULL, N'asc';"
        $errorLogResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $errorLogQuery -ErrorAction SilentlyContinue -MaxRows 5

        if ($errorLogResult) {
            $resultDetails += "Error Log 확인: 최근 로그 존재"
        }
    }
    catch {
        $resultDetails += "감사 상태 확인 실패: $($_.Exception.Message)"
    }
}

$inspection_summary = "MSSQL 감사 로깅 확인`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. 서버 감사(Server Audit) 확인:`r`n"
$inspection_summary += "   SELECT name, is_state_enabled FROM sys.server_audits;`r`n`r`n"
$inspection_summary += "2. 서버 감사 사양 확인:`r`n"
$inspection_summary += "   SELECT name, is_state_enabled FROM sys.server_audit_specifications;`r`n`r`n"
$inspection_summary += "3. Error Log 확인:`r`n"
$inspection_summary += "   EXEC xp_readerrorlog;`r`n`r`n"
$inspection_summary += "4. SSMS 확인:`r`n"
$inspection_summary += "   - Security > Audits`r`n"
$inspection_summary += "   - Management > SQL Server Logs`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. 서버 감사 생성:`r`n"
$inspection_summary += "   CREATE SERVER AUDIT audit_name TO FILE (FILEPATH = ''C:\Audit'');`r`n`r`n"
$inspection_summary += "2. 감사 활성화:`r`n"
$inspection_summary += "   ALTER SERVER AUDIT audit_name WITH (STATE = ON);`r`n`r`n"
$inspection_summary += "3. 감사 사양 생성:`r`n"
$inspection_summary += "   - 로그인 감사 (SUCCESSFUL_LOGIN_GROUP, FAILED_LOGIN_GROUP)`r`n"
$inspection_summary += "   - 권한 변경 감사 (DATABASE_ROLE_MEMBER_CHANGE_GROUP)`r`n"
$inspection_summary += "   - 스키마 변경 감사 (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP)`r`n`r`n"
$inspection_summary += "4. 로그 정기 검토 (월 1회 이상 권장)`r`n"
$inspection_summary += "5. 로그 보관 (1년 이상 권장)`r`n`r`n"
$inspection_summary += "검증 결과:`r`n"
$inspection_summary += ($resultDetails -join "`r`n")

$commandExecuted = "SELECT name, is_state_enabled FROM sys.server_audits;"
$command_result = $resultDetails -join "`n"

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
