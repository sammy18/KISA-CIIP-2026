# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-22
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 하
# @Title       : 데이터베이스의 자원 제한 기능을 TRUE로 설정
# @Description : Oracle 전용 항목으로 MSSQL에서는 N/A 처리
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-22"
$ITEM_NAME = "데이터베이스의 자원 제한 기능을 TRUE로 설정"
$SEVERITY = "하"
$CATEGORY = "3.옵션관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'RESOURCE _LIMIT 값을 TRUE로 설정하여 자원의 과도한 사용을 방지하여 데이터베이스의 안정성을 보장하고, 효율적인 자원 관리를 수행하기 위함'
$threat = '자원 제한 기능을 TRUE로 설정하지 않을 경우, 특정 사용자가 과도하게 많은 자원을 소비할 수 있으며 이로 인해 시스템에 과부하가 발생할 위험이 존재함'
$criteria_good = 'RESOURCE _LIMIT 설정이 TRUE로 되어 있는 경우'
$criteria_bad = 'RESOURCE _LIMIT 설정이 FALSE로 되어 있는 경우'
$remediation = 'RESOURCE _LIMIT 설정을 TRUE로 설정 변경'

# N/A 반환 (Oracle 전용 항목)
$diagnosis_result = "NA"
$status = "N/A"
$inspection_summary = "이 항목은 Oracle에만 해당되는 점검 항목입니다."
$command_result = "MSSQL에서는 해당 기능이 적용되지 않아 N/A 처리"
$commandExecuted = "N/A"

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
