

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-03
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 상
# @Title       : 불필요한계정제거
# @Description : 불필요한 계정 제거를 통해 시스템 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-03"
$ITEM_NAME = "불필요한계정제거"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check for unnecessary accounts
# 참고: KISA 가이드라인에 구체적 기준이 없어, 업계 표준(90일) 적용
try {
    $builtinAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
    $currentDate = Get-Date
    $daysThreshold = 90  # 업계 표준: 90일 이상 미사용 계정을 불필요한 계정으로 간주
    $unnecessaryAccounts = @()

    # Get all local users
    $allUsers = Get-LocalUser

    foreach ($user in $allUsers) {
        # Skip built-in accounts
        if ($user.Name -in $builtinAccounts) {
            continue
        }

        # Check if account is disabled
        if ($user.Enabled -eq $false) {
            # Get last logon time using WMI (locale-independent)
            try {
                $lastLogonWmi = Get-WmiObject -Class Win32_NetworkLoginProfile -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq $user.Name } |
                    Sort-Object LastLogon -Descending |
                    Select-Object -FirstObject -ExpandProperty LastLogon

                if ($lastLogonWmi) {
                    $lastLogonDate = [Management.ManagementDateTimeConverter]::ToDateTime($lastLogonWmi)
                    $daysSinceLogon = ($currentDate - $lastLogonDate).Days

                    if ($daysSinceLogon -gt $daysThreshold) {
                        $unnecessaryAccounts += "$($user.Name) (비활성화, $($daysSinceLogon)일 미로그온)"
                    }
                } else {
                    # Cannot determine last logon, include disabled account for review
                    $unnecessaryAccounts += "$($user.Name) (비활성화, 로그온 기록 없음)"
                }
            } catch {
                # If last logon cannot be determined, mark for manual review
                $unnecessaryAccounts += "$($user.Name) (비활성화, 확인 필요)"
            }
        }
    }

    $commandExecuted = "Get-LocalUser; Get-WmiObject -Class Win32_NetworkLoginProfile | Where-Object { $_.Name -eq $user.Name } | Select-Object -FirstObject -ExpandProperty LastLogon"

    if ($unnecessaryAccounts.Count -gt 0) {
        $accountList = $unnecessaryAccounts -join ', '
        $finalResult = "VULNERABLE"
        $summary = "불필요한 계정 발견 ($($unnecessaryAccounts.Count)개): $accountList`n`n기준: 90일 이상 로그온 없는 비활성화 계정"
        $status = "취약"
        $commandOutput = $accountList
    } else {
        $finalResult = "GOOD"
        $summary = "시스템에 불필요한 계정이 존재하지 않음 (90일 이상 미로그온 비활성화 계정 기준)"
        $status = "양호"
        $commandOutput = "No unnecessary accounts found (90-day threshold applied)"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalUser; net user [accountname]"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "퇴직, 전직, 휴직 등의 이유로 사용하지 않는 계정, 불필요한 계정 및 의심스러운 계정을 삭제하여, 일반적으로 로그인이 필요치 않은 해당 계정들을 통한 로그인을 차단하고, 계정의 패스워드 추측 공격 시도를차단하기위함"
$threat = "관리되지 않은 불필요한 계정은 장기간 비밀번호가 변경되지 않아 무차별 대입 공격(Brute Force Attack)이나 비밀번호 추측 공격(Password Guessing Attack)의 가능성이 존재하며, 또한 이런 공격으로계정정보가유출되어도유출사실을인지하기어려워초기대응이불가능한위험이존재함"
$criteria_good = "불필요한계정이존재하지않는경우"
$criteria_bad = "불필요한계정이존재하는경우"
$remediation = "현재계정현황확인후불필요한계정삭제"

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

# run_all 모드가 아닐 때만 완료 메시지 출력
if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($finalResult)"
}

exit 0
