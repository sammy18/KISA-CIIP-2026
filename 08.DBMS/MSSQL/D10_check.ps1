# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 원격에서DB서버로의접속제한
# @Description : 불필요한 접속 경로 제한 및 접근 통제
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-10"
$ITEM_NAME = "원격에서DB서버로의접속제한"
$SEVERITY = "상"
$CATEGORY = "2.접근제어"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '지정된 IP 주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검하여 비인가자의 DB 서버 접근을 원천적으로 차단하고자함'
$threat = 'DB 서버 접속 시 IP 주소 제한이 적용되지 않은 경우 비인가자가 내·외부 망 위치에 상관없이 DB 서버에 접근할 수 있는 위험이 존재함'
$criteria_good = 'DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한한 경우'
$criteria_bad = 'DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한하지 않은 경우'
$remediation = 'DB 서버에 대해 지정된 IP 주소에서만 접근 가능하도록 설정'

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

# 방화벽 규칙 확인
$inspection_summary = "MSSQL 원격 접속 제한 확인`r`n`r`n"
$inspection_summary += "검증 방법:`r`n`r`n"
$inspection_summary += "1. SQL Server Configuration Manager:`r`n"
$inspection_summary += "   - SQL Server Network Configuration > Protocols for MSSQLSERVER`r`n"
$inspection_summary += "   - Properties > IP Addresses 탭`r`n"
$inspection_summary += "   - IPAll > TCP Dynamic Ports: 비움`r`n"
$inspection_summary += "   - IPAll > TCP Port: 특정 포트 지정`r`n`r`n"
$inspection_summary += "2. Windows 방화벽 규칙 확인:`r`n"
$inspection_summary += "   - PowerShell: Get-NetFirewallRule | Where-Object {`$_.DisplayName -like ''*SQL*''}`r`n"
$inspection_summary += "   - 양호: 특정 IP 주소에서만 허용하는 규칙 존재`r`n"
$inspection_summary += "   - 취약: 모든 IP(0.0.0.0/0)에서 접속 허용`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. SQL Server Configuration Manager에서 IP 제한 설정`r`n"
$inspection_summary += "2. Windows Firewall에서 특정 IP만 허용하는 인바운드 규칙 생성`r`n"
$inspection_summary += "3. 원격 접속이 필요없으면 TCP/IP 비활성화"

$commandExecuted = "Get-NetFirewallRule | Where-Object {`$_.DisplayName -like '*SQL*'} | Select-Object DisplayName, Enabled, Direction"
$firewallRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*SQL*' } | Select-Object DisplayName, Enabled, Direction | Out-String

if ($firewallRules) {
    $inspection_summary += "`r`n`r`n검증 결과:`r`n$firewallRules"
    $command_result = $firewallRules
}

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
