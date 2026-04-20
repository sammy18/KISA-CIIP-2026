# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 응용프로그램또는DBA계정의Role이Public으로설정되지않도록조정
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-18"
$ITEM_NAME = "응용프로그램또는DBA계정의Role이Public으로설정되지않도록조정"
$SEVERITY = "상"
$CATEGORY = "2.접근제어"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '응용 프로그램 또는 DBA 계정의 Role을 점검하여 일반 계정으로 응용 프로그램 테이블이나 DBA 테이블의 접근을 차단하기 위함'
$threat = '응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정된 경우 일반 계정에서도 응용 프로그램 테이블 및 DBA 테이블로 접근할 수 있으므로 중요 정보 유출의 위험이 존재함'
$criteria_good = 'DBA 계정의 Role이 Public으로 설정되지 않은 경우'
$criteria_bad = 'DBA 계정의 Role이 Public으로 설정된 경우'
$remediation = 'DBA 계정의 Role 설정에서 Public 그룹 권한 취소'

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
    # public 역할 권한 확인
    try {
        $publicRoleQuery = @"
SELECT
    dp.state_desc,
    dp.permission_name,
    dp.class_desc,
    OBJECT_NAME(dp.major_id) AS object_name
FROM sys.database_permissions dp
WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
  AND dp.permission_name NOT IN ('CONNECT')
ORDER BY dp.permission_name;
"@
        $publicRoleResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $publicRoleQuery -ErrorAction SilentlyContinue

        if ($publicRoleResult) {
            $publicPermissions = @($publicRoleResult)
            $resultDetails += "public 역할 부여 권한 수: $($publicPermissions.Count)"
            foreach ($perm in $publicPermissions) {
                $resultDetails += "  - $($perm.permission_name) on $($perm.object_name)"
            }
        } else {
            $resultDetails += "public 역할: 최소 권한만 부여 (양호)"
        }
    }
    catch {
        $resultDetails += "public 역할 확인 실패: $($_.Exception.Message)"
    }
}

$inspection_summary = "MSSQL public 역할 권한 점검`r`n`r`n"
$inspection_summary += "이 항목은 Oracle PUBLIC role 전용 항목입니다. MSSQL은 public 역할이 존재하지만 Oracle과 다른 권한 모델을 사용합니다.`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. public 역할 권한 확인:`r`n"
$inspection_summary += "   SELECT permission_name, state_desc`r`n"
$inspection_summary += "   FROM sys.database_permissions`r`n"
$inspection_summary += "   WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public');`r`n`r`n"
$inspection_summary += "2. 서버 수준 public 권한 확인:`r`n"
$inspection_summary += "   SELECT class_desc, permission_name, state_desc`r`n"
$inspection_summary += "   FROM sys.server_permissions`r`n"
$inspection_summary += "   WHERE grantee_principal_id = SUSER_SID('public');`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. 불필요한 권한 제거: REVOKE [permission] TO public;`r`n"
$inspection_summary += "2. public 역할에서 CONNECT SQL만 유지 권장`r`n`r`n"
$inspection_summary += "검증 결과:`r`n"
$inspection_summary += ($resultDetails -join "`r`n")

$commandExecuted = "SELECT * FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public');"
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
