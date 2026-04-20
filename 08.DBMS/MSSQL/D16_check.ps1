# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-16
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 하
# @Title       : Windows 인증 모드 사용
# @Description : MSSQL Server가 Windows 인증 모드만 사용하도록 설정되어 있는지 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-16"
$ITEM_NAME = "Windows 인증 모드 사용"
$SEVERITY = "하"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '적절한 Windows 인증 모드를 적용하여 적합한 복잡성 수준을 유지하기 위함'
$threat = '혼합 인증 모드를 사용하고 sa 계정이 활성화되어 있는 경우, 잘 알려진 sa 계정에 대한 계정 추측 공격의 위험이 존재함'
$criteria_good = 'Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우'
$criteria_bad = '혼합 인증 모드를 사용하고, 활성화된 sa 계정에 대한 강력한 암호 정책 설정을 하지 않은 경우'
$remediation = 'Windows 인증 모드 사용'

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

# 진단 수행
$inspection_summary = "MSSQL 인증 모드 점검`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. SQL Server Management Studio:`r`n"
$inspection_summary += "   - 서버 우클릭 > Properties > Security`r`n"
$inspection_summary += "   - Server authentication 확인`r`n`r`n"
$inspection_summary += "2. 레지스트리 확인:`r`n"
$inspection_summary += "   - 경로: HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLXX.MSSQLServer\SuperSocketNetLib`r`n"
$inspection_summary += "   - 값 이름: LoginMode`r`n"
$inspection_summary += "   - 1: Windows 인증만 (양호)`r`n"
$inspection_summary += "   - 2: 혼합 모드 (취약)`r`n`r`n"
$inspection_summary += "3. T-SQL 확인:`r`n"
$inspection_summary += "   SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsWindowsOnly;`r`n"
$inspection_summary += "   - 1: Windows 인증만 (양호)`r`n"
$inspection_summary += "   - 0: 혼합 모드 (취약)`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. SSMS: Server Properties > Security > Windows Authentication mode 선택`r`n"
$inspection_summary += "2. T-SQL:`r`n"
$inspection_summary += "   EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',`r`n"
$inspection_summary += "   N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1;`r`n"
$inspection_summary += "3. 서비스 재시작 필요"

if ($connectionSuccess) {
    $authModeQuery = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsWindowsOnly;"
    $commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query `"$authModeQuery`""

    try {
        $authResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $authModeQuery -ErrorAction SilentlyContinue
        if ($authResult) {
            $isWindowsOnly = $authResult.IsWindowsOnly
            $command_result = "IsIntegratedSecurityOnly: $isWindowsOnly"

            if ($isWindowsOnly -eq 1) {
                $inspection_summary += "`r`n`r`n검증 결과: Windows 인증 모드만 사용 (양호)"
                $diagnosis_result = "GOOD"
                $status = "양호"
            } else {
                $inspection_summary += "`r`n`r`n검증 결과: 혼합 인증 모드 사용 (취약)"
                $diagnosis_result = "VULNERABLE"
                $status = "취약"
            }
        }
    }
    catch {
        $inspection_summary += "`r`n`r`n검증 결과: 확인 실패 (수동 진단 필요)"
        $command_result = $_.Exception.Message
    }
}

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
