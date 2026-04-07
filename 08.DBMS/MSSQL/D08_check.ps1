# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 안전한암호화알고리즘사용
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-08"
$ITEM_NAME = "안전한암호화알고리즘사용"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '안전한 해시 알고리즘 사용으로 데이터의 기밀성 및 무결성을 보장하고, 사용자 인증을 강화하기 위함'
$threat = 'SHA-1이나 MD5와 같은 오래된 알고리즘 사용 시 공격자의 무차별 대입 공격 등으로 비밀번호 유추가 가능하며, 데이터 변조 및 유출의 위험이 존재함'
$criteria_good = '해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우'
$criteria_bad = '해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우'
$remediation = 'SHA-256 이상의 암호화 알고리즘 적용'

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

if (-not $connectionSuccess) {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요. SQL Server Management Studio에서 다음 쿼리 실행: SELECT name, password_hash FROM sys.sql_logins;"
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
    # SQL Server 버전 확인
    $versionQuery = "SELECT SERVERPROPERTY('productversion') AS ProductVersion, SERVERPROPERTY('productlevel') AS ProductLevel, SERVERPROPERTY('edition') AS Edition;"
    $versionResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $versionQuery -ErrorAction SilentlyContinue

    if ($versionResult) {
        $productVersion = $versionResult.ProductVersion
        $majorVersion = [int]($productVersion.Split('.')[0])

        $resultDetails += "SQL Server 버전: $($versionResult.Edition) ($productVersion)"

        # MSSQL 2012 (11.x) 이상은 SHA-512 사용
        if ($majorVersion -ge 11) {
            $resultDetails += "암호화 알고리즘: SHA-512 (양호)"
        }
        elseif ($majorVersion -ge 10) {
            $resultDetails += "암호화 알고리즘: SHA-512 (양호, MSSQL 2008)"
        }
        else {
            $resultDetails += "암호화 알고리즘: SHA-1 (취약, MSSQL 2005 이전)"
            $diagnosis_result = "VULNERABLE"
            $status = "취약"
        }
    }

    $inspection_summary = "MSSQL 암호화 알고리즘 확인`r`n`r`n"
    $inspection_summary += "암호화 알고리즘 정보:`r`n"
    $inspection_summary += "- MSSQL 2012 이상: SHA-512 (32bit Salt 적용) - 양호`r`n"
    $inspection_summary += "- MSSQL 2008: SHA-512 - 양호`r`n"
    $inspection_summary += "- MSSQL 2005 이전: SHA-1 - 취약`r`n`r`n"
    $inspection_summary += "검증 방법:`r`n"
    $inspection_summary += "1. SQL Server 버전 확인:`r`n"
    $inspection_summary += "   SELECT SERVERPROPERTY('productversion') AS ProductVersion;`r`n`r`n"
    $inspection_summary += "2. 비밀번호 해시 확인:`r`n"
    $inspection_summary += "   SELECT name, password_hash FROM sys.sql_logins;`r`n`r`n"
    $inspection_summary += "참고: MSSQL 2012 이상에서는 기본적으로 SHA-512를 사용하므로 추가 설정 불필요`r`n`r`n"
    $inspection_summary += ($resultDetails -join "`r`n")
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

if ($diagnosis_result -eq "MANUAL") {
    $diagnosis_result = "GOOD"
    $status = "양호"
}

$commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT SERVERPROPERTY(''productversion'');'"

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
