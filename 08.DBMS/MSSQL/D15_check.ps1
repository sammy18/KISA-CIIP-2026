# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-15
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 하
# @Title       : 관리자이외의사용자가오라클리스너의접속을통해리스너로그및trace파일에대한변경제한
# @Description : 불필요한 접속 경로 제한 및 접근 통제
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-15"
$ITEM_NAME = "관리자이외의사용자가오라클리스너의접속을통해리스너로그및trace파일에대한변경제한"
$SEVERITY = "하"
$CATEGORY = "3.파일관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '관리자이외의사용자가오라클리스너의접속을통해리스너로그및trace파일에대한변경을제한하는지점검'
$threat = '관리자이외의사용자가리스너로그및trace파일에접근할수있는경우비인가자가DBMS의정보를열람할수있는위험이존재함'
$criteria_good = '관리자이외의사용자가리스너의접속을통해리스너로그및trace파일에대한변경이제한된경우'
$criteria_bad = '관리자이외의사용자가리스너의접속을통해리스너로그및trace파일에대한변경이제한되지않은경우'
$remediation = 'listener.ora설정파일에서ADMIN_RESTRICTIONS_listener명=ON설치'

# 변수 초기화
$diagnosis_result = "NA"
$status = "N/A"
$inspection_summary = "이 항목은 Oracle에만 해당되는 점검 항목입니다. MSSQL에서는 해당 사항 없음"
$command_result = "N/A - Oracle-specific feature not applicable to MSSQL"
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
