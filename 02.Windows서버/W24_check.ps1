# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-24
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : FTP접근제어설정
# @Description : FTP 서비스의 IP 기반 접근 제어로 무단 접속 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-24"
$ITEM_NAME = "FTP접근제어설정"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check FTP IP restriction settings
try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $ftpSite = Get-Website -Name 'FTP*' -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ftpSite) {
        $ipSecurity = Get-WebConfiguration -Filter '/system.ftpServer/security/ipSecurity' -PSPath 'IIS:\' -ErrorAction SilentlyContinue

        if ($ipSecurity -and ($ipSecurity.AllowUnlisted -eq $false -or $ipSecurity.ChildElements.Count -gt 0)) {
            $finalResult = "GOOD"
            $summary = "FTP 서비스에 IP 제한 설정이 적용됨"
            $status = "양호"
            $ipRestrictionDetails = "AllowUnlisted: $($ipSecurity.AllowUnlisted)"
            if ($ipSecurity.ChildElements.Count -gt 0) {
                $ipRestrictionDetails += "; Rules configured: $($ipSecurity.ChildElements.Count)"
            }
            $commandOutput = $ipRestrictionDetails
        } else {
            $finalResult = "VULNERABLE"
            $summary = "FTP 서비스에 IP 주소 기반 접근 제한이 설정되지 않음"
            $status = "취약"
            $commandOutput = if ($ipSecurity) { "No IP restrictions configured; AllowUnlisted: $($ipSecurity.AllowUnlisted)" } else { "IP Security not configured" }
        }
    } else {
        $finalResult = "GOOD"
        $summary = "FTP 서비스가 설치되지 않음 또는 FTP 사이트가 구성되지 않음"
        $status = "양호"
        $commandOutput = "No FTP site configured"
    }

    $commandExecuted = "Get-WebConfiguration -Filter '/system.ftpServer/security/ipSecurity' -PSPath 'IIS:\'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter '/system.ftpServer/security/ipSecurity' -PSPath 'IIS:\'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "FTP접근시특정IP주소에대해콘텐츠접근을허용하여서비스보안성을강화하기위함"
$threat = "FTP 프로토콜은 로그온 시 지정된 자격 증명이나 데이터 자체가 암호화되지 않고 모든 자격 증명을 일반텍스트로네트워크를통해전송되는특성상서버클라이언트간트래픽스니핑을통해인증정보가 쉽게노출될위험이존재함"
$criteria_good = "특정IP주소에서만FTP서버에접속하도록접근제어설정을적용한경우"
$criteria_bad = "특정IP주소에서만FTP서버에접속하도록접근제어설정을적용하지않는경우 ※조치시마스터속성과모든사이트에적용함"
$remediation = "특정IP주소에서만FTP서버에접속하도록접근제어설정"

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
