

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-11
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 최신보안패치및벤더권고사항적용WindowsOSBuild점검
# @Description : 최신 보안 패치 및 벤더 권고 사항 적용 및 Windows OS Build 버전 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-11"
$ITEM_NAME = "최신보안패치및벤더권고사항적용WindowsOSBuild점검"
$SEVERITY = "상"
$CATEGORY = "3.패치관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $command = 'Get-CimInstance Win32_OperatingSystem'
    $os = Get-CimInstance Win32_OperatingSystem
    $caption = $os.Caption
    $build = [int]$os.BuildNumber

    $displayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
    $releaseId = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ReleaseId

    $commandResult = "OS: $caption | Build: $build"
    if ($displayVersion) { $commandResult += " | DisplayVersion: $displayVersion" }
    if ($releaseId) { $commandResult += " | ReleaseId: $releaseId" }

    if ($build -ge 22000) {
        $finalResult = "GOOD"
        $summary = "Windows 11 Build $build - 최신 지원 버전 사용 중"
        $status = "양호"
    } elseif ($build -ge 19044) {
        $finalResult = "GOOD"
        $summary = "Windows 10 Build $build 이상 지원"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "Windows 10 Build $build 미지원 버전"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandResult = $_.Exception.Message
}

# 2. Define guideline variables
$purpose = '최신 서비스팩이 적용되어 있는지 점검하여 시스템 취약점을 이용한 공격(익스플로잇)에 대비가 되어있는지확인하기위함'
$threat = '최신 서비스팩이 적용되지 않았을 경우 비인가자의 시스템 취약점을 이용한 공격(익스플로잇)에 노출될 수있는위험이존재함'
$criteria_good = '최신빌드가적용되어있고내부적으로관리절차를수립하여이행한경우'
$criteria_bad = '최신빌드가적용되어있지않거나내부적으로관리절차가수립되지않은경우'
$remediation = 'WindowsUpdate사이트에접속하여최신서비스팩여부확인및적용'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandResult `
    -CommandExecuted $command `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
