# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-09
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 중
# @Title       : 일정횟수의로그인실패시이에대한잠금정책설정
# @Description : 보안 감사 로그 기록 및 관리를 통한 추적성 확보
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-09"
$ITEM_NAME = "일정횟수의로그인실패시이에대한잠금정책설정"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'DBMS 설정 중 일정 횟수의 로그인 실패 시 계정 잠금 정책에 대한 설정이 되어있는지 점검'
$threat = '일정한 횟수의 로그인 실패 횟수를 설정하여 제한하지 않으면 자동화된 방법으로 계정 및 비밀번호를 획득하여 데이터베이스에 접근하여 정보가 유출될 위험이 존재함'
$criteria_good = '로그인 시도 횟수를 제한하는 값을 설정한 경우'
$criteria_bad = '로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우'
$remediation = '로그인 시도 횟수 제한값 설정'

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

# Windows 계정 잠금 정책 확인
$inspection_summary = "MSSQL 로그인 잠금 정책 확인`r`n`r`n"
$inspection_summary += "MSSQL은 Windows 계정 정책을 따르므로 계정 잠금 정책 설정 필요`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. Windows 로컬 보안 정책 실행:`r`n"
$inspection_summary += "   - secpol.msc 실행`r`n"
$inspection_summary += "   - 보안 설정 > 계정 정책 > 계정 잠금 정책`r`n`r`n"
$inspection_summary += "2. 계정 잠금 임계값(Account Lockout Threshold) 확인:`r`n"
$inspection_summary += "   - 양호: 3~5회 이하로 설정 (예: 3 = 3회 실패 시 잠금)`r`n"
$inspection_summary += "   - 취약: 0으로 설정 (잠금 정책 없음)`r`n`r`n"
$inspection_summary += "3. 계정 잠금 기간(Account Lockout Duration) 확인:`r`n"
$inspection_summary += "   - 권장: 15분~30분 (예: 30 = 30분 동안 잠금)`r`n`r`n"
$inspection_summary += "4. 잠금 카운터 재설정 시간(Reset Account Lockout Counter After) 확인:`r`n"
$inspection_summary += "   - 계정 잠금 기간과 동일하게 설정 권장`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. 계정 잠금 임계값: 3~5회 설정`r`n"
$inspection_summary += "2. 계정 잠금 기간: 15~30분 설정`r`n"
$inspection_summary += "3. 잠금 카운터 재설정 시간: 잠금 기간과 동일하게 설정`r`n`r`n"
$inspection_summary += "참고:`r`n"
$inspection_summary += "- Windows 인증 모드 사용 시 Windows 계정 정책 적용`r`n"
$inspection_summary += "- SQL Server 인증 사용 시 별도 정책 설정 필요"

$commandExecuted = "net accounts"
$command_result = & net.exe 2>&1

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
