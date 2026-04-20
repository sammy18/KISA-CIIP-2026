# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-03"
$ITEM_NAME = "비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '비밀번호 사용 기간 및 복잡 도 설정 유무를 점검하여 비인가자의 비밀번호 추측 공격(무차별 대입 공격, 사전 대입 공격 등)에 대한 대비가 되어 있는지 확인하기 위함'
$threat = '비밀번호 사용 기간 및 복잡 도 설정이 되어 있지 않으면 비인가자가 비밀번호 추측 공격을 통해 획득한 계정의 비밀번호를 이용하여 DB에 접근할 수 있는 위험이 존재함'
$criteria_good = '기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용된 경우'
$criteria_bad = '기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용되지 않은 경우'
$remediation = '기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 정책 설정'

# 변수 초기화
$diagnosis_result = "UNKNOWN"
$status = "미진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
$vulnerabilities_found = 0
$resultDetails = @()

# SQL Server 모듈 로드
try {
    Import-Module SqlServer -ErrorAction SilentlyContinue
}
catch {
    # SqlServer 모듈이 없으면 sqlcmd 사용
}

# SQL Server 서비스 확인
$mssqlService = Get-Service | Where-Object { $_.Name -like '*SQL*' -and $_.Status -eq 'Running' } | Select-Object -First 1

if (-not $mssqlService) {
    $diagnosis_result = "N/A"
    $status = "N/A"
    $inspection_summary = "SQL Server 서비스가 실행 중이 아닙니다."
    $command_result = "SQL Server service not found or not running"
    $commandExecuted = "Get-Service | Where-Object { `$_.Name -like '*SQL*' }"

    Save-DualResult -ItemId $ITEM_ID `
        -ItemName $ITEM_NAME `
        -Status $status `
        -FinalResult $diagnosis_result `
        -InspectionSummary $inspection_summary `
        -CommandResult $command_result `
        -CommandExecuted $commandExecuted `
        -GuidelinePurpose $purpose `
        -GuidelineThreat $threat `
        -GuidelineCriteriaGood $criteria_good `
        -GuidelineCriteriaBad $criteria_bad `
        -GuidelineRemediation $remediation `
        -ScriptDir $SCRIPT_DIR

    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($diagnosis_result)"
    exit 0
}

# SQL Server 연결
$serverName = $env:COMPUTERNAME
$connectionSuccess = $false

try {
    $testQuery = "SELECT 1"
    $result = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $testQuery -ErrorAction SilentlyContinue
    if ($result) {
        $connectionSuccess = $true
    }
}
catch {
    $connectionSuccess = $false
}

if (-not $connectionSuccess) {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요"
    $command_result = "연결 실패: Server=$serverName"
    $commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master"

    Save-DualResult -ItemId $ITEM_ID `
        -ItemName $ITEM_NAME `
        -Status $status `
        -FinalResult $diagnosis_result `
        -InspectionSummary $inspection_summary `
        -CommandResult $command_result `
        -CommandExecuted $commandExecuted `
        -GuidelinePurpose $purpose `
        -GuidelineThreat $threat `
        -GuidelineCriteriaGood $criteria_good `
        -GuidelineCriteriaBad $criteria_bad `
        -GuidelineRemediation $remediation `
        -ScriptDir $SCRIPT_DIR

    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($diagnosis_result)"
    exit 0
}

# 진단 수행
try {
    # 1. SQL Server 비밀번호 정책 확인
    $policyQuery = @"
SELECT
    name,
    description,
    value_in_use
FROM sys.configurations
WHERE name IN (
    'password policy',
    'password expiration enabled',
    'password complexity',
    'lockout time',
    'lockout threshold'
)
ORDER BY name;
"@

    $policyResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $policyQuery -ErrorAction SilentlyContinue

    if ($policyResult) {
        $resultDetails += "SQL Server 비밀번호 정책:"
        foreach ($policy in $policyResult) {
            $resultDetails += "  - $($policy.name): $($policy.value_in_use)"

            # 정책이 비활성화되어 있는지 확인
            if ($policy.name -eq "password complexity" -and $policy.value_in_use -eq 0) {
                $vulnerabilities_found++
                $vulnerabilities += "비밀번호 복잡도 정책 비활성화"
            }
            if ($policy.name -eq "password expiration enabled" -and $policy.value_in_use -eq 0) {
                $vulnerabilities_found++
                $vulnerabilities += "비밀번호 만료 정책 비활성화"
            }
        }
    }

    # 2. LOGIN 개별 정책 확인 (CHECK_POLICY 등)
    $loginPolicyQuery = @"
SELECT
    name,
    is_policy_checked,
    is_expiration_checked
FROM sys.sql_logins
WHERE type = 'S'
  AND name NOT LIKE '##%'
ORDER BY name;
"@

    $loginPolicyResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $loginPolicyQuery -ErrorAction SilentlyContinue

    if ($loginPolicyResult) {
        $noPolicyCount = 0
        $noExpirationCount = 0

        foreach ($login in $loginPolicyResult) {
            if ($login.is_policy_checked -eq 0) {
                $noPolicyCount++
            }
            if ($login.is_expiration_checked -eq 0) {
                $noExpirationCount++
            }
        }

        if ($noPolicyCount -gt 0) {
            $vulnerabilities_found++
            $vulnerabilities += "CHECK_POLICY 비활성화 계정: ${noPolicyCount}개"
        }

        if ($noExpirationCount -gt 0) {
            $vulnerabilities_found++
            $vulnerabilities += "비밀번호 만료 정책 비활성화 계정: ${noExpirationCount}개"
        }

        $resultDetails += ""
        $resultDetails += "SQL 로그인 정책 요약:"
        $resultDetails += "  - 전체 계정 수: $($loginPolicyResult.Count)"
        $resultDetails += "  - CHECK_POLICY 비활성화: ${noPolicyCount}개"
        $resultDetails += "  - 만료 정책 비활성화: ${noExpirationCount}개"
    }

    # 3. Windows Server 비밀번호 정책 확인 (SQL Server가 사용하는 Windows 계정)
    try {
        $netAccounts = & net accounts.exe 2>&1
        if ($netAccounts) {
            $resultDetails += ""
            $resultDetails += "Windows 비밀번호 정책:"
            foreach ($line in $netAccounts) {
                if ($line -match "(최소|최대|잠금|기간|복잡도)") {
                    $resultDetails += "  - $line"
                }
            }
        }
    }
    catch {
        # Windows 명령 실패 시 무시
    }
}
catch {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 진단 중 오류 발생: $($_.Exception.Message). 수동으로 확인하세요."
    $command_result = $_.Exception.Message
    $commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master"

    Save-DualResult -ItemId $ITEM_ID `
        -ItemName $ITEM_NAME `
        -Status $status `
        -FinalResult $diagnosis_result `
        -InspectionSummary $inspection_summary `
        -CommandResult $command_result `
        -CommandExecuted $commandExecuted `
        -GuidelinePurpose $purpose `
        -GuidelineThreat $threat `
        -GuidelineCriteriaGood $criteria_good `
        -GuidelineCriteriaBad $criteria_bad `
        -GuidelineRemediation $remediation `
        -ScriptDir $SCRIPT_DIR

    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($diagnosis_result)"
    exit 0
}

# 최종 판정
if ($vulnerabilities_found -gt 0) {
    $diagnosis_result = "VULNERABLE"
    $status = "취약"
    $inspection_summary = "비밀번호 정책 미설정: " + ($vulnerabilities -join ", ")
}
else {
    $diagnosis_result = "GOOD"
    $status = "양호"
    $inspection_summary = "비밀번호 정책이 적절히 설정됨. " + ($resultDetails -join "; ")
}

$commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT * FROM sys.configurations WHERE name LIKE ''%password%'';'"

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $diagnosis_result `
    -InspectionSummary $inspection_summary `
    -CommandResult ($resultDetails -join "`n") `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($diagnosis_result)"

exit 0
