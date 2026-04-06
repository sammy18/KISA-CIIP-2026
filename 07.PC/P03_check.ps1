

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-03
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 복구콘솔에서자동로그온을금지하도록설정
# @Description : 시스템 복구 시 자동 로그온을 금지하여 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-03"
$ITEM_NAME = "복구콘솔에서자동로그온을금지하도록설정"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableAutomaticRebootLogon'
$commandOutput = ""
try {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $regName = 'DisableAutomaticRebootLogon'

    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
    if ($value.DisableAutomaticRebootLogon -eq 1) {
        $finalResult = "GOOD"
        $summary = "복구 콘솔 자동 로그온 금지 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "복구 콘솔 자동 로그온 금지 설정 안 됨"
        $status = "취약"
    }
    $commandOutput = reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRebootLogon 2>&1 | Out-String
} catch {
    $finalResult = "VULNERABLE"
    $summary = "복구 콘솔 자동 로그온 금지 설정 안 됨"
    $status = "취약"
    $commandOutput = "레지스트리 값 없음 또는 진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '복구콘솔자동로그온허용을''사용안함''으로설정함으로써비인가자의복구콘솔을통한관리자권한 탈취등의위험을방지하기위함'
$threat = 'Windows 복구 콘솔(Recovery Console) 자동로그온설정은시스템액세스허가전Administrator 계정의 비밀번호 제공 여부를 결정하는 것으로 이 옵션을 사용하면 비인가자도 복구 콘솔을 이용해 관리자권한으로시스템에자동으로로그온할수있는위험이존재함'
$criteria_good = '복구콘솔자동로그온허용이''사용안함''으로설정된경우'
$criteria_bad = '복구콘솔자동로그온허용이''사용''으로설정된경우'
$remediation = '복구콘솔자동로그온허용''사용안함''으로설정'

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
