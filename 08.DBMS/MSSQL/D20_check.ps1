# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 하
# @Title       : 인가되지않은Object Owner의제한
# @Description : 인가되지않은Object Owner의제한 관리를 통한 DBMS 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-20"
$ITEM_NAME = "인가되지않은Object Owner의제한"
$SEVERITY = "하"
$CATEGORY = "2.접근제어"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'Object Owner가 비인가자에게 존재하고 있는 경우 중요 데이터에 대한 무단 접근이 가능하여 데이터의 일관성 및 무결성을 해치는 위험이 발생할 수 있으므로 비인가된 계정의 Object Owner를 제한하여 내부 및 외부의 보안 위협을 최소화하기 위함'
$threat = 'Object Owner는 SYS, SYSTEM과 같은 데이터베이스 관리자 계정과 응용 프로그램의 관리자 계정에만 존재하여야하며, 일반 계정이 존재할 경우 공격자가 이를 이용하여 Object의 수정, 삭제가 가능하므로 중요 정보의 유출 및 변경의 위험이 존재함'
$criteria_good = 'ObjectOwner가 SYS,SYSTEM, 관리자 계정 등으로 제한된 경우'
$criteria_bad = 'ObjectOwner가 일반 사용자에게도 존재하는 경우'
$remediation = 'Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정'

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
    # Object Owner 확인
    try {
        $ownerQuery = @"
SELECT
    SCHEMA_NAME(schema_id) AS schema_name,
    name AS object_name,
    type_desc,
    USER_NAME(principal_id) AS owner
FROM sys.objects
WHERE is_ms_shipped = 0
  AND USER_NAME(principal_id) NOT IN ('dbo', 'sys', 'INFORMATION_SCHEMA')
ORDER BY schema_name, object_name;
"@
        $ownerResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $ownerQuery -ErrorAction SilentlyContinue

        if ($ownerResult) {
            $nonDboObjects = @($ownerResult)
            $resultDetails += "비-dbo 소유자 객체 수: $($nonDboObjects.Count)"

            if ($nonDboObjects.Count -gt 0) {
                foreach ($obj in $nonDboObjects) {
                    $resultDetails += "  - $($obj.schema_name).$($obj.object_name): 소유자=$($obj.owner)"
                }
            } else {
                $resultDetails += "모든 객체가 dbo 소유 (양호)"
            }
        }
    }
    catch {
        $resultDetails += "Object Owner 확인 실패: $($_.Exception.Message)"
    }
}

$inspection_summary = "MSSQL Object Owner 제한 확인`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. 비-dbo 소유자 객체 확인:`r`n"
$inspection_summary += "   SELECT schema_name(schema_id) AS schema_name, name AS object_name, type_desc, USER_NAME(principal_id) AS owner`r`n"
$inspection_summary += "   FROM sys.objects`r`n"
$inspection_summary += "   WHERE is_ms_shipped = 0 AND USER_NAME(principal_id) NOT IN ('dbo', 'sys', 'INFORMATION_SCHEMA');`r`n`r`n"
$inspection_summary += "결과 분석:`r`n"
$inspection_summary += "- 양호: 결과 없음 (모든 객체가 dbo, sys 소유)`r`n"
$inspection_summary += "- 취약: 비-dbo 소유자의 객체 발견`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. 객체 소유자를 dbo로 변경:`r`n"
$inspection_summary += "   ALTER AUTHORIZATION ON OBJECT::schema.table TO dbo;`r`n"
$inspection_summary += "   ALTER AUTHORIZATION ON SCHEMA::schema_name TO dbo;`r`n`r`n"
$inspection_summary += "2. 전체 데이터베이스 객체 소유자 일괄 변경:`r`n"
$inspection_summary += "   EXEC sp_MSforeachtable @command1='ALTER AUTHORIZATION ON OBJECT::''?'' TO dbo;'`r`n`r`n"
$inspection_summary += "검증 결과:`r`n"
$inspection_summary += ($resultDetails -join "`r`n")

$commandExecuted = "SELECT schema_name(schema_id) AS schema_name, name AS object_name, USER_NAME(principal_id) AS owner FROM sys.objects WHERE is_ms_shipped = 0;"
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
