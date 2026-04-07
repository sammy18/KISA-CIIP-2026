# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 중
# @Title       : root권한으로서비스구동제한
# @Description : 과도한 권한 부여 방지 및 최소 권한 원칙 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-07"
$ITEM_NAME = "root권한으로서비스구동제한"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'root 권한을 제한적으로 사용함으로써 시스템의 손상, 데이터의 유출 및 변조 등을 차단하여 보안 위협을 방지하기 위함'
$threat = 'root 권한으로 서비스를 구동할 경우 시스템 손상, 데이터 유출 및 변조, 감사 및 추적의 어려움 등으로 인해 서비스 공격의 표적이 될 위험이 존재함'
$criteria_good = 'DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우'
$criteria_bad = 'DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우'
$remediation = 'DBMS 구동 계정 변경'

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

# MSSQL 서비스 계정 확인
$inspection_summary = "MSSQL 서비스 계정 권한 점검`r`n`r`n"
$inspection_summary += "검증 방법:`r`n`r`n"
$inspection_summary += "1. SQL Server Configuration Manager 실행:`r`n"
$inspection_summary += "   - SQL Server Services > SQL Server(MSSQLSERVER) > 속성`r`n`r`n"
$inspection_summary += "2. ''Built-in account'' 또는 ''This account'' 확인:`r`n"
$inspection_summary += "   - 양호: Local System, Local Service, Network Service 이외의 전용 계정 사용`r`n"
$inspection_summary += "   - 취약: Local System 계정 사용 (권한 상승 위험)`r`n`r`n"
$inspection_summary += "3. PowerShell 명령어로 확인:`r`n"
$inspection_summary += "   Get-WmiObject win32_service | Where-Object {`$_.Name -like ''*SQL*''} | Select-Object Name, StartName, State`r`n`r`n"
$inspection_summary += "보안 가이드:`r`n"
$inspection_summary += "- Local System: 최고 권한 (사용 권장하지 않음)`r`n"
$inspection_summary += "- Network Service: 네트워크 리소스 접근 가능`r`n"
$inspection_summary += "- Local Service: 제한된 로컬 권한 (권장)`r`n"
$inspection_summary += "- 전용 서비스 계정: 최소 권한으로 구성 (가장 권장)`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. SQL Server Configuration Manager 실행`r`n"
$inspection_summary += "2. SQL Server 서비스 > 속성 > 로그온 탭`r`n"
$inspection_summary += "3. ''This account'' 선택 > 전용 서비스 계정 입력`r`n"
$inspection_summary += "4. 서비스 재시작"

$commandExecuted = "Get-WmiObject win32_service | Where-Object {`$_.Name -like '*SQL*'} | Select-Object Name, StartName, State"
$command_result = Get-WmiObject win32_service | Where-Object { $_.Name -like '*SQL*' } | Select-Object Name, StartName, State | Out-String

if ($command_result) {
    $inspection_summary += "`r`n`r`n검증 결과:`r`n$command_result"
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
