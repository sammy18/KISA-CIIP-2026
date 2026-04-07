# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 기본계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 초기 설치 시 생성되는 기본 계정(sa 등)의 기본 비밀번호
#                변경 여부 및 기본 권한 정책의 적절성을 점검합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-01"
$ITEM_NAME = "기본계정의 비밀번호, 정책 등을 변경하여 사용"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무를 점검하여 비인가자의 초기 비밀번호 대입 공격을 차단하고 있는지 확인하기 위함'
$threat = 'DBMS 기본 계정 초기 비밀번호 및 권한 정책을 변경하지 않을 경우 비인가자가 인터넷 통해 DBMS 기본 계정의 초기 비밀번호를 획득하여 초기 비밀번호를 그대로 사용하고 있는 DB에 접근하여 기본 계정에 부여된 권한의 취약점을 이용하여 DB 정보를 유출할 수 있는 위험이 존재함'
$criteria_good = '기본 계정의 초기 비밀번호를 변경하거나 잠금 설정한 경우'
$criteria_bad = '기본 계정의 초기 비밀번호를 변경하지 않거나 잠금 설정을 하지 않은 경우'
$remediation = '기본(관리자)계정의 초기 비밀번호 및 권한 정책 변경'

# 변수 초기화
$diagnosis_result = "UNKNOWN"
$status = "미진단"
$inspection_summary = ""
$command_result = ""
$command_executed = ""
$vulnerabilities_found = 0

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

# SQL Server 연결 시도
$serverName = $env:COMPUTERNAME
$connectionSuccess = $false

try {
    # 연결 테스트
    $testQuery = "SELECT 1"
    if (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue) {
        $result = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $testQuery -ErrorAction SilentlyContinue
        if ($result) {
            $connectionSuccess = $true
        }
    }
}
catch {
    # 연결 실패 - sqlcmd 사용 시도
}

# 진단 수행
$resultDetails = @()
$vulnerabilities = @()

try {
    # 1. 게스트 사용자 계정 확인
    try {
        $guestQuery = "SELECT name, type_desc FROM sys.server_principals WHERE name LIKE '%guest%' AND is_disabled = 0;"
        $guestResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $guestQuery -ErrorAction SilentlyContinue
        if ($guestResult) {
            foreach ($guest in $guestResult) {
                $vulnerabilities += "활성화된 게스트 사용자: $($guest.name)"
                $vulnerabilities_found++
            }
        }
    }
    catch {
        $resultDetails += "게스트 사용자 확인 실패: $($_.Exception.Message)"
    }

    # 2. sa 계정 상태 확인
    try {
        $saQuery = "SELECT name, is_disabled FROM sys.server_principals WHERE name = 'sa';"
        $saResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $saQuery -ErrorAction SilentlyContinue
        if ($saResult) {
            if ($saResult.is_disabled -eq 0) {
                $vulnerabilities += "sa 계정이 활성화됨 (비밀번호 설정 확인 필요)"
            } else {
                $resultDetails += "sa 계정이 비활성화됨 (양호)"
            }
        }
    }
    catch {
        $resultDetails += "sa 계정 확인 실패: $($_.Exception.Message)"
    }

    # 3. sysadmin 역할에 속한 계정 확인
    try {
        $sysadminQuery = "SELECT name FROM sys.server_principals WHERE type = 'S' AND is_disabled = 0 AND principal_id IN (SELECT member_principal_id FROM sys.server_role_members WHERE role_principal_id = 3);"
        $sysadminResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $sysadminQuery -ErrorAction SilentlyContinue
        if ($sysadminResult) {
            $sysadminCount = ($sysadminResult | Measure-Object).Count
            $resultDetails += "sysadmin 역할 계정 수: $sysadminCount"
            foreach ($admin in $sysadminResult) {
                $resultDetails += "  - $($admin.name)"
            }
        }
    }
    catch {
        $resultDetails += "sysadmin 확인 실패: $($_.Exception.Message)"
    }

    # 4. 빈 비밀번호 확인 (MSSQL 2012+)
    try {
        $emptyPwdQuery = "SELECT name FROM sys.sql_logins WHERE is_disabled = 0 AND PWDCOMPARE('', password_hash) = 1;"
        $emptyPwdResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $emptyPwdQuery -ErrorAction SilentlyContinue
        if ($emptyPwdResult) {
            foreach ($empty in $emptyPwdResult) {
                $vulnerabilities += "빈 비밀번호 계정: $($empty.name)"
                $vulnerabilities_found++
            }
        }
    }
    catch {
        $resultDetails += "빈 비밀번호 확인 실패: $($_.Exception.Message)"
    }

    # 5. 정책 확인 (Password policy, Lockout)
    try {
        $policyQuery = "SELECT name, value_in_use FROM sys.configurations WHERE name LIKE '%password%' OR name LIKE '%lockout%';"
        $policyResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $policyQuery -ErrorAction SilentlyContinue
        if ($policyResult) {
            $resultDetails += "보안 정책 설정:"
            foreach ($policy in $policyResult) {
                $resultDetails += "  - $($policy.name): $($policy.value_in_use)"
            }
        }
    }
    catch {
        $resultDetails += "정책 확인 실패: $($_.Exception.Message)"
    }

}
catch {
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "SQL Server 진단 중 오류 발생: $($_.Exception.Message). 수동으로 확인하세요."
    $command_result = $_.Exception.Message
    $commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName"

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
    $inspection_summary = "기본 계정 보안 취약 발견: " + ($vulnerabilities -join ", ")
}
else {
    $diagnosis_result = "GOOD"
    $status = "양호"
    $inspection_summary = "기본 계정이 적절히 관리됨. " + ($resultDetails -join "; ")
}

$commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'SELECT * FROM sys.server_principals;'"

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
