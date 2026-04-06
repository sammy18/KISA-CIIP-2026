# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-42
# @Category    : Windows Server
# @Platform    : Windows Server 2008, 2012, 2016, 2019, 2022
# @Severity    : 하
# @Title       : 이벤트로그관리설정
# @Description : 이벤트 로그 파일 크기 및 보관 기간 적절 유지로 중요 로그 누락 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-42"
$ITEM_NAME = "이벤트로그관리설정"
$SEVERITY = "하"
$CATEGORY = "4.로그관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check event log maximum size settings
try {
    $logNames = @('Application', 'System', 'Security')
    $logDetails = @()
    $allConfigured = $true

    foreach ($logName in $logNames) {
        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if ($log) {
            $maxSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $logDetails += "$logName : $($log.MaximumSizeInBytes) bytes ($maxSizeMB MB)"

            if ($log.MaximumSizeInBytes -lt 10485760) {  # 10,240 KB = 10,485,760 bytes
                $allConfigured = $false
            }
        } else {
            $allConfigured = $false
            $logDetails += "$logName : 접근 불가"
        }
    }

    if ($allConfigured) {
        $finalResult = "GOOD"
        $summary = "최대 로그 크기가 10,240KB 이상으로 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "최대 로그 크기가 10,240KB 미만으로 설정됨"
        $status = "취약"
    }

    $commandExecuted = "Get-WinEvent -ListLog Application, System, Security"
    $commandOutput = $logDetails -join "`n"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WinEvent -ListLog Application, System, Security"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "유사시 책임추적을 위해 주요 이벤트가 누락 되지 않도록 이벤트 로그 파일의 크기 및 보관 기간을 적절하게유지하기위함"
$threat = "이벤트 로그 파일의 크기가 충분하지 않으면 중요 로그가 저장되지 않을 위험이 있으며, 최대 보존 크기를초과하는경우자동으로덮어씀으로써중요로그의손실위험이존재함"
$criteria_good = "최대로그크기'10,240KB이상'으로설정,'90일이후이벤트덮어씀'을설정한경우"
$criteria_bad = "최대로그크기'10,240KB미만'으로설정,이벤트덮어씀기간이'90일이하로설정된경우"
$remediation = "최대로그크기'10,240KB','90일이후이벤트덮어씀'설정"

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
