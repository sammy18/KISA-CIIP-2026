

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-17
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 하드디스크기본공유제거
# @Description : 하드디스크 기본 공유(C$, D$, ADMIN$) 제거 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-17"
$ITEM_NAME = "하드디스크기본공유제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check default administrative shares (C$, D$, ADMIN$)
try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
    $autoShare = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).AutoShareServer

    $defaultShares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^\w+\$' -and $_.Name -ne 'IPC$'
    }

    $shareNames = ($defaultShares | ForEach-Object { $_.Name }) -join ', '

    if ($autoShare -eq 0 -and ($defaultShares.Count -eq 0)) {
        $finalResult = "GOOD"
        $summary = "레지스트리 AutoShareServer가 0이며 기본 공유(C$, D$, ADMIN$ 등)가 존재하지 않음"
        $status = "양호"
        $commandOutput = "AutoShareServer = 0, No default shares found"
    } elseif ($autoShare -eq 1 -or ($defaultShares.Count -gt 0)) {
        $finalResult = "VULNERABLE"
        $summary = "레지스트리 AutoShareServer가 1이거나 기본 공유(C$, D$, ADMIN$ 등)가 존재함 (보안 위협)"
        $status = "취약"
        $commandOutput = "AutoShareServer = $autoShare, Default shares: $shareNames"
    } else {
        $finalResult = "GOOD"
        $summary = "기본 공유가 존재하지 않음"
        $status = "양호"
        $commandOutput = "No default shares found"
    }

    $commandExecuted = "reg query '$path' /v AutoShareServer"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "reg query '$path' /v AutoShareServer"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "하드디스크기본공유를제거하여시스템정보노출을차단하고자함"
$threat = "Windows는 프로그램 및 서비스를 네트워크나 컴퓨터 환경에서 관리하기 위해 시스템 기본 공유 항목을자동으로생성함.이를제거하지않으면비인가자가모든시스템자원에접근할수있는위험한 상황이발생할수있으며이러한공유기능의경로를이용하여바이러스가침투위험이존재함"
$criteria_good = "레지스트리의AutoShareServer (WinNT: AutoShareWks)가0이며기본공유가존재하지않 는경우"
$criteria_bad = "레지스트리의AutoShareServer (WinNT: AutoShareWks)가1이거나기본공유가존재하는 경우"
$remediation = "기본공유중지후레지스트리값설정(IPC$,일반공유제외)"

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
