# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금 설정 후 사용
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-02"
$ITEM_NAME = "데이터베이스의 불필요 계정을 제거하거나, 잠금 설정 후 사용"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '불필요한 계정 존재 유무를 점검하여 불필요한 계정 정보(비밀번호)의 유출 시 발생할 수 있는 비인가자의 DB 접근에 대비되어 있는지 확인하기 위함'
$threat = 'DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재할 경우, 비인가자가 불필요한 계정을 이용하여 DB에 접근하여 데이터를 열람, 삭제, 수정할 위험이 존재함'
$criteria_good = '계정 정보를 확인하여 불필요한 계정이 없는 경우'
$criteria_bad = '인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 불필요한 계정이 존재하는 경우'
$remediation = '계정별 용도를 파악한 후 불필요한 계정 삭제'

# 변수 초기화
$diagnosis_result = "UNKNOWN"
$status = "미진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""

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
    $diagnosis_result = "N/A"
    $status = "N/A"
    $inspection_summary = "SQL Server 서비스가 실행 중이 아닙니다."
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
    # 연결 테스트
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
    $commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT 1'"

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
$vulnerabilities_found = 0
$vulnerabilities = @()
$resultDetails = @()

try {
    # 1. 빈 비밀번호 계정 확인 (MSSQL 2012+)
    $emptyPwdQuery = "SELECT name FROM sys.sql_logins WHERE is_disabled = 0 AND PWDCOMPARE('', password_hash) = 1;"
    $emptyPwdResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $emptyPwdQuery -ErrorAction SilentlyContinue

    if ($emptyPwdResult) {
        foreach ($user in $emptyPwdResult) {
            $vulnerabilities += "빈 비밀번호 계정: $($user.name)"
            $vulnerabilities_found++
        }
    }

    # 2. 비활성화되지 않은 오래된 계정 확인 (90일 이상 미로그온)
    $oldAccountQuery = @"
SELECT name,
       CREATE_DATE,
       DATEDIFF(day, MAX(login_time), GETDATE()) as days_since_login
FROM sys.sql_logins
WHERE is_disabled = 0
  AND name NOT LIKE '##%'
  AND DATEDIFF(day, CREATE_DATE, GETDATE()) > 90
GROUP BY name, CREATE_DATE
HAVING MAX(login_time) IS NULL OR DATEDIFF(day, MAX(login_time), GETDATE()) > 90;
"@
    $oldAccountResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $oldAccountQuery -ErrorAction SilentlyContinue

    if ($oldAccountResult) {
        foreach ($account in $oldAccountResult) {
            $vulnerabilities += "장기 미사용 계정 (90일+): $($account.name)"
            $vulnerabilities_found++
        }
    }

    # 3. 게스트 사용자 계정 확인
    $guestQuery = "SELECT name, type_desc FROM sys.server_principals WHERE name LIKE '%guest%' AND is_disabled = 0;"
    $guestResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $guestQuery -ErrorAction SilentlyContinue

    if ($guestResult) {
        foreach ($guest in $guestResult) {
            $vulnerabilities += "활성화된 게스트 사용자: $($guest.name)"
            $vulnerabilities_found++
        }
    }

    # 4. 전체 계정 목록
    $allAccountsQuery = "SELECT name, type_desc, is_disabled, create_date FROM sys.sql_logins WHERE type = 'S' AND name NOT LIKE '##%' ORDER BY name;"
    $allAccountsResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $allAccountsQuery -ErrorAction SilentlyContinue

    if ($allAccountsResult) {
        $resultDetails += "전체 SQL 로그인 계정:"
        foreach ($account in $allAccountsResult) {
            $status = if ($account.is_disabled -eq 1) { "비활성" } else { "활성" }
            $resultDetails += "  - $($account.name): $($account.type_desc), $($status)"
        }
    }
}
catch {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 진단 중 오류 발생: $($_.Exception.Message). 수동으로 확인하세요."
    $command_result = $_.Exception.Message
    $commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT * FROM sys.sql_logins;'"

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
    $inspection_summary = "불필요한 계정 발견: " + ($vulnerabilities -join ", ")
}
else {
    $diagnosis_result = "GOOD"
    $status = "양호"
    $inspection_summary = "불필요한 계정 없음. " + ($resultDetails -join "; ")
}

$commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT * FROM sys.sql_logins;'"

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
