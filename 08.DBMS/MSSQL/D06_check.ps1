# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 중
# @Title       : DB사용자계정을개별적으로부여하여사용
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-06"
$ITEM_NAME = "DB사용자계정을개별적으로부여하여사용"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '사용자별 별도 DBMS 계정을 사용하여 DB에 접근하는지 점검하여 DB 계정 공유 사용으로 발생할 수 있는 로그 감사 추적 문제를 대비하고자함'
$threat = 'DB 계정을 공유하여 사용할 경우 비인가자의 DB 접근 발생 시 계정 공유 사용으로 인해 로그 감사 추적의 어려움이 발생할 위험이 존재함'
$criteria_good = '사용자별 계정을 사용하고 있는 경우'
$criteria_bad = '공용 계정을 사용하고 있는 경우'
$remediation = '사용자별 계정 생성 및 권한 부여'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
$vulnerabilities_found = 0
$vulnerabilities = @()
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

if (-not $connectionSuccess) {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요. SQL Server Management Studio에서 다음 쿼리 실행: SELECT name, type_desc, create_date FROM sys.server_principals WHERE type IN (''S'', ''U'') AND name NOT IN (''sa'', ''##MS_Agent##'') ORDER BY name;"
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
try {
    # 1. 의심스러운 공용 계정 확인
    $sharedAccountQuery = @"
SELECT name, type_desc, create_date, modify_date
FROM sys.server_principals
WHERE type = 'S'
  AND (name LIKE '%shared%' OR name LIKE '%common%' OR name LIKE '%public%' OR name LIKE '%test%' OR name LIKE '%demo%')
  AND is_disabled = 0
  AND name NOT IN ('sa', 'guest', 'PUBLIC');
"@

    $sharedAccountResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $sharedAccountQuery -ErrorAction SilentlyContinue

    if ($sharedAccountResult) {
        foreach ($account in $sharedAccountResult) {
            $vulnerabilities += "의심스러운 공용 계정: $($account.name)"
            $vulnerabilities_found++
        }
    }

    # 2. 다중 사용자 연결 확인
    $multiSessionQuery = @"
SELECT login_name, COUNT(*) as session_count
FROM sys.dm_exec_sessions
WHERE is_user_process = 1
GROUP BY login_name
HAVING COUNT(*) > 5
ORDER BY session_count DESC;
"@

    $multiSessionResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $multiSessionQuery -ErrorAction SilentlyContinue

    if ($multiSessionResult) {
        foreach ($session in $multiSessionResult) {
            $resultDetails += "다중 세션 계정: $($session.login_name) - $($session.session_count)개 세션"
        }
    }

    # 3. 전체 계정 목록
    $allAccountsQuery = "SELECT name, type_desc, is_disabled, create_date FROM sys.server_principals WHERE type IN ('S', 'U') AND name NOT LIKE '##%' ORDER BY name;"
    $allAccountsResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $allAccountsQuery -ErrorAction SilentlyContinue

    if ($allAccountsResult) {
        $resultDetails += "전체 계정 수: $($allAccountsResult.Count)"
    }
}
catch {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 진단 중 오류 발생: $($_.Exception.Message). 수동으로 확인하세요."
    $command_result = $_.Exception.Message
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

# 최종 판정
if ($vulnerabilities_found -gt 0) {
    $diagnosis_result = "VULNERABLE"
    $status = "취약"
    $inspection_summary = "공용 계정 발견: " + ($vulnerabilities -join ", ")
}
else {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "공용 계정 자동 점검 완료. 추가 검증 필요: 응용 프로그램별, 사용자별 계정 분리 여부 확인. " + ($resultDetails -join "; ")
}

$commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT * FROM sys.server_principals;'"

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $diagnosis_result `
    -InspectionSummary $inspection_summary `
    -CommandResult ($resultDetails -join "`n") `
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
