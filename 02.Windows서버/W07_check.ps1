

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-07
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : Everyone사용권한을익명사용자에게적용
# @Description : Everyone 사용권한이 익명사용자에게 적용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-07"
$ITEM_NAME = "Everyone사용권한을익명사용자에게적용"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check EveryoneIncludesAnonymous policy
try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).EveryoneIncludesAnonymous

    if ($value -eq 0) {
        $finalResult = "GOOD"
        $summary = "'Everyone 사용 권한을 익명 사용자에게 적용' 정책이 '사용 안 함'으로 설정됨"
        $status = "양호"
        $commandOutput = "EveryoneIncludesAnonymous = 0 (Disabled)"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'Everyone 사용 권한을 익명 사용자에게 적용' 정책이 '사용'으로 설정됨 (보안 위협)"
        $status = "취약"
        $commandOutput = "EveryoneIncludesAnonymous = $value (Enabled)"
    }

    $commandExecuted = "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "익명 사용자가Everyone그룹으로사용권한을준모든리소스에접근하는것을차단하여비인가자에 의한접근가능성을제한하기위함"
$threat = "해당 정책이 '사용'으로 설정될 경우 권한이 없는 사용자가 익명으로 계정 이름 및 공유 리소스를 나열하고 이 정보를 사용하여 암호를 추측하거나 DoS(Denial of Service) 공격을 실행할 위험이 존재함"
$criteria_good = "'Everyone사용권한을익명사용자에게적용'정책이'사용안함'으로되어있는경우"
$criteria_bad = "'Everyone사용권한을익명사용자에게적용'정책이'사용'으로되어있는경우"
$remediation = "'Everyone사용권한을익명사용자에게적용'정책을'사용안함'으로설정"

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
    -GuidelineRemediation $remediation

# run_all 모드가 아닐 때만 완료 메시지 출력
if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($finalResult)"
}

exit 0
