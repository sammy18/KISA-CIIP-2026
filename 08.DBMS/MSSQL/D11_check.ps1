# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : DBA이외의인가되지않은사용자가시스템테이블에접근할수없도록설정
# @Description : 불필요한 접속 경로 제한 및 접근 통제
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-11"
$ITEM_NAME = "DBA이외의인가되지않은사용자가시스템테이블에접근할수없도록설정"
$SEVERITY = "상"
$CATEGORY = "2.접근제어"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '시스템 테이블의 일반 사용자 계정 접근 제한 설정 적용 여부를 점검하여 일반 사용자 계정 유출 시 발생할 수 있는 비인가자의 시스템 테이블 접근 위험을 차단하기 위함'
$threat = '시스템 테이블의 일반 사용자 계정 접근 제한 설정이 되어 있지 않을 경우 Object, 사용자, 테이블 및 뷰, 작업 내역 등의 시스템 테이블에 저장된 정보가 누출될 수 있음'
$criteria_good = '시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우'
$criteria_bad = '시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우'
$remediation = '시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""

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

if (-not $connectionSuccess) {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요"
    $command_result = "연결 실패: Server=$serverName"
    $commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master"

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

# 진단 수행
$inspection_summary = "MSSQL 시스템 테이블 접근 권한 점검`r`n`r`n"
$inspection_summary += "검증 방법:`r`n`r`n"
$inspection_summary += "1. 일반 사용자의 시스템 테이블 접근 권한 확인:`r`n"
$inspection_summary += "   SELECT user_name(grantee_principal_id) AS principal_name,`r`n"
$inspection_summary += "          class_desc, permission_name`r`n"
$inspection_summary += "   FROM sys.database_permissions`r`n"
$inspection_summary += "   WHERE major_id IN (SELECT object_id FROM sys.objects WHERE schema_id = SCHEMA_ID('sys'))`r`n"
$inspection_summary += "   AND user_name(grantee_principal_id) NOT IN ('dbo', 'sysadmin', 'db_owner')`r`n`r`n"
$inspection_summary += "2. public 역할에 부여된 시스템 테이블 권한 확인:`r`n"
$inspection_summary += "   SELECT permission_name, state_desc`r`n"
$inspection_summary += "   FROM sys.database_permissions`r`n"
$inspection_summary += "   WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public')`r`n"
$inspection_summary += "   AND major_id IN (SELECT object_id FROM sys.objects WHERE schema_id = SCHEMA_ID('sys'))`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. 불필요한 권한 확인 후 REVOKE 명령어로 제거`r`n"
$inspection_summary += "2. REVOKE SELECT ON sys.table_name FROM [user_name]`r`n"
$inspection_summary += "3. 시스템 뷰/저장 프로시저를 통해서만 접근 허용"

$commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT * FROM sys.database_permissions;'"

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
