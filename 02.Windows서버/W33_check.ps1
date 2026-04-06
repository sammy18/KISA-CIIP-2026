# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-33
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 하
# @Title       : HTTP/FTP/SMTP배너차단
# @Description : HTTP/FTP/SMTP 서비스 배너 정보 노출 차단으로 불필요한 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-33"
$ITEM_NAME = "HTTP/FTP/SMTP배너차단"
$SEVERITY = "하"
$CATEGORY = "2.서비스관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}
Write-Host ""

# Diagnostic Logic
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $iisInstalled = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue

    if ($iisInstalled -and $iisInstalled.InstallState -eq 'Installed') {
        $bannerFound = $false

        # Check HTTP banner
        $httpBanner = Get-WebConfigurationProperty -Filter 'system.webServer/httpProtocol' -Name 'customHeaders' -ErrorAction SilentlyContinue
        if ($httpBanner) {
            foreach ($header in $httpBanner.Collection) {
                if ($header.Name -eq 'Server') {
                    $bannerFound = $true
                }
            }
        }

        # Check FTP installation
        $ftpInstalled = Get-WindowsFeature -Name Web-Ftp-Server -ErrorAction SilentlyContinue
        if ($ftpInstalled -and $ftpInstalled.InstallState -eq 'Installed') {
            $bannerFound = $true
        }

        if ($bannerFound) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "HTTP/FTP/SMTP 서비스 배너 정보가 노출됨"
            $commandOutput = "Banner information exposed in HTTP/FTP/SMTP services"
        } else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "HTTP/FTP/SMTP 서비스 배너 정보가 차단됨"
            $commandOutput = "Banner information properly blocked"
        }

        $commandExecuted = "Get-WindowsFeature -Name Web-Server; Get-WebConfigurationProperty -Filter 'system.webServer/httpProtocol'"
    } else {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "IIS/FTP/SMTP 서비스가 설치되어 있지 않음"
        $commandExecuted = "Get-WindowsFeature -Name Web-Server"
        $commandOutput = "IIS/FTP/SMTP services not installed"
    }

} catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "진단 실패: 수동 확인 필요"
    $commandExecuted = "Get-WindowsFeature -Name Web-Server; Get-WebConfigurationProperty -Filter 'system.webServer/httpProtocol'"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "HTTP/FTP/SMTP서비스접속배너를통한불필요한정보노출을방지하기위함"
$threat = "서비스 접속 배너가 차단되지 않는 경우 임의의 사용자가 HTTP, FTP, SMTP 접속 시도 시 노출되는 접속배너정보를수집하여악의적인공격에이용할위험이존재함"
$criteria_good = "HTTP,FTP,SMTP접속시배너정보가보이지않는경우"
$criteria_bad = "HTTP,FTP,SMTP접속시배너정보가보이는경우"
$remediation = "사용하지않는경우IIS서비스중지/사용안함,사용시속성값수정"

# Save results using lib
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

exit 0
