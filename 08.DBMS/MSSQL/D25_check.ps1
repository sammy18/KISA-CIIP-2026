# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 주기적보안패치및벤더권고사항적용
# @Description : MSSQL 보안패치 적용 현황 및 최신 버전 사용 여부 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-25"
$ITEM_NAME = "주기적보안패치및벤더권고사항적용"
$SEVERITY = "상"
$CATEGORY = "4.패치관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '안전한 버전의 데이터 베이스를 사용하여 알려진 보안 취약점으로 인한 공격을 차단하기 위함'
$threat = '안전하지 않은 버전을 사용할 경우, 알려진 보안 취약점을 통해 시스템에 침투하거나 데이터의 탈취, 악성 코드 감염 및 서비스 중단 등의 보안 사고를 초래할 위험이 존재함'
$criteria_good = '보안 패치가 적용된 버전을 사용하는 경우'
$criteria_bad = '보안 패치가 적용되지 않는 버전을 사용하는 경우'
$remediation = '보안 패치가 적용된 버전으로 업데이트'

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
    # 버전 확인
    try {
        $versionQuery = "SELECT SERVERPROPERTY('productversion') AS ProductVersion, SERVERPROPERTY('productlevel') AS ProductLevel, SERVERPROPERTY('edition') AS Edition;"
        $versionResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $versionQuery -ErrorAction SilentlyContinue

        if ($versionResult) {
            $productVersion = $versionResult.ProductVersion
            $productLevel = $versionResult.ProductLevel
            $edition = $versionResult.Edition
            $majorVersion = [int]($productVersion.Split('.')[0])

            $resultDetails += "SQL Server 버전: $productVersion"
            $resultDetails += "에디션: $edition"
            $resultDetails += "업데이트 레벨: $productLevel"
        }
    }
    catch {
        $resultDetails += "버전 확인 실패: $($_.Exception.Message)"
    }
}

$inspection_summary = "SQL Server 보안패치 적용 확인 (수동진단 권장)`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. 현재 버전 확인:`r`n"
$inspection_summary += "   SELECT SERVERPROPERTY('productversion') AS ProductVersion;`r`n`r`n"
$inspection_summary += "2. 최신 버전 확인:`r`n"
$inspection_summary += "   - Microsoft SQL Server Downloads: https://learn.microsoft.com/en-us/sql/sql-server/sql-server-downloads`r`n"
$inspection_summary += "   - Latest Update: https://sqlserverupdates.org/`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. SQL Server Downloads 또는 SQL Server Updates에서 최신 CU/SP 확인`r`n"
$inspection_summary += "2. 누적 업데이트(CU) 또는 서비스 팩(SP) 다운로드`r`n"
$inspection_summary += "3. 테스트 환경에서 업데이트 검증`r`n"
$inspection_summary += "4. 프로덕션 환경에 업데이트 적용`r`n"
$inspection_summary += "5. 주기적 업데이트 (분기 1회 이상 권장)`r`n`r`n"
$inspection_summary += "검증 결과:`r`n"
$inspection_summary += ($resultDetails -join "`r`n")

$commandExecuted = "SELECT SERVERPROPERTY('productversion') AS ProductVersion;"
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
