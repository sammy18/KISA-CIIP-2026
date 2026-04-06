# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-05
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 중
# @Title       : 비밀번호재사용에대한제약설정
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-05"
$ITEM_NAME = "비밀번호재사용에대한제약설정"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '비밀번호 변경 시 이전 비밀번호를 재사용할 수 없도록 비밀번호 제약 설정이 되어있는지 점검'
$threat = '비밀번호 재사용 제약 설정이 적용되어 있지 않을 경우 비밀번호 변경 전 사용했던 비밀번호를 재사용함으로써 비인가자의 계정 비밀번호 추측 공격에 대한 시간을 더 많이 허용하여 비밀번호 유출 위험이 증가함'
$criteria_good = 'Windows 비밀번호 정책에서 비밀번호 기억 설정이 적용된 경우'
$criteria_bad = '비밀번호 재사용 제한 설정이 적용되지 않은 경우'
$remediation = 'Windows 로컬 보안 정책 > 계정 정책 > 비밀번호 정책 > ''비밀번호 기억'' 값 설정'

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

# Windows 비밀번호 정책 확인
$inspection_summary = "MSSQL 비밀번호 재사용 제약 설정 확인`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. Windows 로컬 보안 정책 실행:`r`n"
$inspection_summary += "   - secpol.msc 실행`r`n"
$inspection_summary += "   - 보안 설정 > 계정 정책 > 비밀번호 정책`r`n`r`n"
$inspection_summary += "2. ''비밀번호 기억(Enforce Password History)'' 설정 확인:`r`n"
$inspection_summary += "   - 양호: 0 이상의 값으로 설정 (예: 24 = 최근 24개 비밀번호 재사용 금지)`r`n"
$inspection_summary += "   - 취약: 0으로 설정 (비밀번호 재사용 제한 없음)`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "''비밀번호 기억'' 값을 24 이상으로 설정`r`n"
$inspection_summary += "- 기본값: 0 (최근 비밀번호 기억 안함)`r`n"
$inspection_summary += "- 권장값: 24 (최근 24개 비밀번호 재사용 금지)`r`n`r`n"
$inspection_summary += "참고: MSSQL은 Windows 비밀번호 정책을 따르므로 CHECK_POLICY와 CHECK_EXPIRATION 옵션이 활성화된 경우 Windows 정책이 적용됨"

# net accounts 명령 실행
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
