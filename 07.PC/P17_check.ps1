

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-17
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 이동식미디어자동실행방지
# @Description : 이동식 미디어 자동 실행 기능을 비활성화하여 악성코드 실행 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-17"
$ITEM_NAME = "이동식미디어자동실행방지"
$SEVERITY = "중"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check autorun settings for removable media
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $regName = "NoDriveTypeAutoRun"

    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue

    if ($value -ne $null) {
        $hexValue = [int]$value.NoDriveTypeAutoRun
        $hexString = "0x$($hexValue.ToString('X2')) ($hexValue)"
        $commandOutput = "$regName : $hexString"

        # 0xFF (255) = Disable autorun on all drives
        # 0xDD (221) = Disable autorun on all drives except CD-ROM
        if ($hexValue -eq 0xFF -or $hexValue -eq 0xDD) {
            $finalResult = "GOOD"
            $summary = "이동식 미디어 자동실행 금지됨 ($hexString)"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "이동식 미디어 자동실행 허용됨 ($hexString, 권장: 0xFF 또는 0xDD)"
            $status = "취약"
        }
    } else {
        $finalResult = "VULNERABLE"
        $summary = "NoDriveTypeAutoRun 레지스트리 값 없음 (자동실행 허용 상태)"
        $status = "취약"
        $commandOutput = "$regName : Not set (default: autorun enabled)"
    }

    $commandExecuted = "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
    $commandExecuted = "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
}

# 2. Define guideline variables
$purpose = 'CD/DVD,USB메모리등과같은이동식미디어를USBport에연결시자동실행을차단하기위함'
$threat = 'Ÿ CD/DVD, USB 메모리등과같은이동식미디어가자동실행되는경우미디어에탑재된''Autorun.i nf''파일을통해다른응용프로그램이자동실행될수있는위험이존재함 Ÿ 이동식미디어가사용될때읽기기능을통해바이러스감염이생길수있고,쓰기기능을통하여주요 정보유출이발생할수있음'
$criteria_good = '미디어사용시자동실행되지않고내부적으로관리절차를수립하여이행된경우'
$criteria_bad = '미디어사용시자동실행되거나내부적으로관리절차가수립되지않은경우'
$remediation = '미디어자동실행방지설정'

# 3. Save results using Save-DualResult
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

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
