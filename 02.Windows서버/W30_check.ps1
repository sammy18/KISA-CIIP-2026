# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-30
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 중
# @Title       : SNMP Community String복잡성설정
# @Description : SNMP Community String 복잡성 설정으로 무단 SNMP 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-30"
$ITEM_NAME = "SNMP Community String복잡성설정"
$SEVERITY = "중"
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

# 1. Run diagnostic
try {
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    $communities = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

    if ($communities) {
        $hasWeakCommunity = $false
        $weakCommunities = @()
        $allCommunities = @()

        foreach ($prop in $communities.PSObject.Properties) {
            # PSObject의 기본 속성(PSPath, PSParentPath 등) 제외
            if ($prop.Name -notmatch '^PS') {
                $allCommunities += "$($prop.Name) (권한: $($prop.Value))"

                # 기본 Community String 확인 (public, private, write, read)
                if ($prop.Name -match 'public|private|write|read' -and $prop.Value -gt 0) {
                    $hasWeakCommunity = $true
                    $weakCommunities += $prop.Name
                }
            }
        }

        $commandOutput = $allCommunities -join "`r`n"

        if ($hasWeakCommunity) {
            $finalResult = "VULNERABLE"
            $weakList = $weakCommunities -join ', '
            $summary = "SNMP Community String이 기본값($weakList)을 사용하여 보안 취약"
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "SNMP Community String이 복잡하게 설정되어 기본값(public, private 등) 미사용"
            $status = "양호"
        }
    } else {
        $finalResult = "GOOD"
        $summary = "SNMP Community String이 설정되지 않음 (서비스 미사용)"
        $status = "양호"
        $commandOutput = "레지스트리 키 없음"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'"

# 2. lib를 통한 결과 저장
$purpose = "SNMP에서 일종의 비밀번호로 사용하는 Community String을 유추할 수 없는 복잡한 값으로 변경하여불필요한시스템정보노출을차단하기위함"
$threat = "Community String을 변경하지않고public, private등기본설정값으로사용하는경우,기본CommunityString값을통한시스템의주요정보및설정상태가비인가자에게노출될수있는위험이 존재함"
$criteria_good = "SNMP 서비스를사용하지않거나CommunityString이public, private이아닌경우"
$criteria_bad = "SNMP 서비스를사용하며,Community String이 public, private인경우"
$remediation = "불필요시서비스중지/사용안함,사용시기본CommunityString변경"

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
