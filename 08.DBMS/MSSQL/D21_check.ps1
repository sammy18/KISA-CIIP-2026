# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : GRANT OPTION 권한이 불필요한 계정에 부여되지 않았는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-21"
$ITEM_NAME = "인가되지 않은 GRANT OPTION 사용 제한"
$SEVERITY = "중"
$CATEGORY = "3.옵션관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'GRANTOPTION을 ROLE에 의해 설정하여 권한의 남용을 방지하고, 안정성을 확보하기 위함'
$threat = '일반 사용자에게 GRANT OPTION이 부여된 경우, 일반 사용자가 Object 소유자인 것과 같이 다른 일반 사용자에게 권한을 부여할 수 있어 권한의 무분별한 확산으로 인한 중요 정보의 유출 등의 위험이 존재함'
$criteria_good = 'WITH _GRANT _OPTION이 ROLE에 의하여 설정된 경우'
$criteria_bad = 'WITH _GRANT _OPTION이 ROLE에 의하여 설정되지 않은 경우'
$remediation = 'WITH _GRANT _OPTION이 ROLE에 의하여 설정되도록 변경'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
$resultDetails = @()
$grantOptionFound = @()

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
    # 1. WITH GRANT OPTION 권한 확인
    try {
        $grantQuery = @"
SELECT dp.name AS UserName, pe.permission_name, pe.state_desc
FROM sys.database_permissions pe
JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id
WHERE pe.state = 'W'
"@
        $grantResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $grantQuery -ErrorAction SilentlyContinue

        if ($grantResult) {
            foreach ($row in $grantResult) {
                $userName = $row.UserName
                $permName = $row.permission_name
                $stateDesc = $row.state_desc
                if ($userName -notin @('dbo', 'sa', 'sys', 'INFORMATION_SCHEMA', 'guest')) {
                    $grantOptionFound += "계정: $userName, 권한: $permName, 상태: $stateDesc"
                }
            }
        }
    }
    catch {
        $resultDetails += "WITH GRANT OPTION 확인 실패: $($_.Exception.Message)"
    }

    # 2. 스키마 소유자 확인
    try {
        $schemaQuery = "SELECT name FROM sys.database_principals WHERE owns_schema = 1 AND name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys');"
        $schemaResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $schemaQuery -ErrorAction SilentlyContinue

        if ($schemaResult) {
            foreach ($row in $schemaResult) {
                $grantOptionFound += "스키마 소유자: $($row.name) (간접적 GRANT 권한 보유 가능)"
            }
        }
    }
    catch {
        $resultDetails += "스키마 소유자 확인 실패: $($_.Exception.Message)"
    }
}

# 최종 판정
if ($grantOptionFound.Count -gt 0) {
    $diagnosis_result = "VULNERABLE"
    $status = "취약"
    $inspection_summary = "WITH GRANT OPTION 권한이 부여된 계정 발견:`r`n"
    $inspection_summary += ($grantOptionFound -join "`r`n")
    $command_result = $grantOptionFound -join "`n"
}
elseif ($connectionSuccess) {
    $diagnosis_result = "GOOD"
    $status = "양호"
    $inspection_summary = "불필요한 계정에 GRANT OPTION이 부여되지 않음"
    $command_result = if ($resultDetails.Count -gt 0) { $resultDetails -join "`n" } else { "WITH GRANT OPTION 권한을 가진 불필요한 계정 없음" }
}
else {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 연결 실패 - 수동 확인 필요`r`n`r`n"
    $inspection_summary += "검증 방법:`r`n"
    $inspection_summary += "SELECT dp.name AS UserName, pe.permission_name, pe.state_desc`r`n"
    $inspection_summary += "FROM sys.database_permissions pe`r`n"
    $inspection_summary += "JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id`r`n"
    $inspection_summary += "WHERE pe.state = 'W';`r`n"
    $command_result = "연결 실패: Server=$serverName"
}

$commandExecuted = "SELECT dp.name AS UserName, pe.permission_name, pe.state_desc FROM sys.database_permissions pe JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id WHERE pe.state = 'W';"

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
