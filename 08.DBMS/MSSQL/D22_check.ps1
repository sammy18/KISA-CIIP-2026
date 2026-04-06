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
$purpose = '데이터베이스 자원 제한 기능을 활성화하여 과도한 자원 사용으로 인한 서비스 거부를 방지하기 위함'
$threat = '자원 제한 기능이 비활성화된 경우 악의적 또는 비정상적인 쿼리로 인해 시스템 자원이 고갈될 위험이 존재함'
$criteria_good = 'RESOURCE_LIMIT가 TRUE로 설정된 경우'
$criteria_bad = 'RESOURCE_LIMIT가 FALSE로 설정된 경우'
$remediation = 'Oracle: ALTER SYSTEM SET RESOURCE_LIMIT=TRUE SCOPE=SPFILE; (Oracle 전용 항목)'

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
