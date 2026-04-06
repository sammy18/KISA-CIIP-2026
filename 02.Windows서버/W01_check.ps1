

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-01
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : Administrator 계정 이름 변경
# @Description : 기본 Administrator 계정 이름을 변경하여 무단 접근 위험 방지 및 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-01"
$ITEM_NAME = "Administrator계정이름변경"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check if Administrator account name is changed
try {
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like "*-500" }

    if ($admin.Name -eq "Administrator") {
        $finalResult = "VULNERABLE"
        $summary = "기본 Administrator 계정 이름 사용 중 (보안 위험)"
        $status = "취약"
    } else {
        $finalResult = "GOOD"
        $summary = "Administrator 계정 이름이 변경됨"
        $status = "양호"
    }

    $commandExecuted = "Get-LocalUser | Where-Object { `$_.SID.Value -like '*-500' }"
    $commandOutput = "Admin Name: $($admin.Name)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalUser | Where-Object { `$_.SID.Value -like '*-500' }"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "윈도우 기본관리자계정인Administrator의이름을변경또는보안을고려한,잘알려진계정을통한 악의적인패스워드추측공격을차단하기위함"
$threat = "Ÿ 일반적으로 관리자 계정으로 잘 알려진 Administrator를 변경하지 않는 경우 악의적인 사용자의 패스워드 추측 공격을 통해 사용 권한 상승의 위험이 있으며, 관리자를 유인하여 침입자의 액세스를 허용하는악성코드를실행할위험이존재함 Ÿ 윈도우 최상위 관리자 계정인 Administrator는 기본적으로 삭제하거나 잠글 수 없어 악의적인 사용자의목표가될위험이존재함"
$criteria_good = "Administrator기본계정이름을변경하거나강화된비밀번호를적용한경우"
$criteria_bad = "Administrator기본계정이름을변경하지않거나단순비밀번호를적용한경우"
$remediation = "Administrator기본계정이름변경및보안성이있는비밀번호설정"

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
