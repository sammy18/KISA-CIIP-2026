

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-05
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 항목의불필요한서비스제거
# @Description : 시스템에서 불필요한 서비스를 제거하여 공격면을 축소
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-05"
$ITEM_NAME = "항목의불필요한서비스제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'Get-Service | Where-Object { $_.Status -eq "Running" }'
$commandOutput = ""
try {
    # KISA 가이드라인 기반 불필요한 서비스 목록 (17개)
    $unnecessaryServices = @(
        "TlntSvr",           # Telnet
        "MSFTPSVC",          # FTP Publishing Service
        "SMTPSVC",           # Simple Mail Transfer Protocol (SMTP)
        "RemoteRegistry",    # Remote Registry Service
        "Simptcp",           # Simple TCP/IP Services
        "Server",            # Server Service (파일 공유)
        "W3SVC",             # World Wide Web Publishing Service (IIS)
        "TermService",       # Terminal Services (RDP) - 일부 환경
        "Schedule",          # Task Scheduler
        "Browser",           # Computer Browser
        "WZCSVC",            # Wireless Configuration
        "upnphost",          # Universal Plug and Play Host
        "SSDPSRV",           # Simple Service Discovery Protocol
        "RemoteAccess",      # Routing and Remote Access
        "Messenger",         # Windows Messenger
        "alerter",           # Alerter Service
        "Clipsrv",           # ClipBook Service
        "fax"                # Fax Service
    )

    $runningServices = Get-Service | Where-Object { $_.Status -eq "Running" -and $_.StartType -ne "Disabled" }
    $foundServices = @()

    foreach ($svc in $runningServices) {
        if ($unnecessaryServices -contains $svc.Name) {
            $foundServices += "$($svc.Name) ($($svc.DisplayName))"
        }
    }

    $serviceOutput = Get-Service | Where-Object { $_.Status -eq "Running" } | Out-String
    $commandOutput = $serviceOutput

    if ($foundServices.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $foundList = $foundServices -join ', '
        $summary = "불필요한 서비스 실행 중 ($($foundServices.Count)개): $foundList"
        $status = "취약"
    } else {
        $finalResult = "GOOD"
        $summary = "불필요한 서비스 실행 중 아님 (KISA 권고 서비스 18개 점검 완료)"
        $status = "양호"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '사용하지않는서비스나기본으로설치된서비스들을제거하여시스템자원의낭비를막고해당서비스 포트를통한침입을방지하기위함'
$threat = 'Ÿ 실질적사용하지않는서비스들이실행되어시스템에과부하가발생하는위험이존재함 Ÿ 불필요한 서비스의 경우 사용자가 알지도 못한 서비스들이 실행되고 있는 경우가 대부분, 이 경우 해당서비스가이미취약한버전의서비스인지도인지하지못하고사용하는위험이존재함'
$criteria_good = '일반적으로불필요한서비스(아래목록참조)가중지된경우'
$criteria_bad = '일반적으로불필요한서비스(아래목록참조)가중지되지않은경우'
$remediation = '불필요한서비스중지설정'

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
