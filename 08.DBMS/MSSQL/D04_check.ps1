# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : 데이터베이스관리자권한을꼭필요한계정및그룹에대해서만허용
# @Description : 관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-04"
$ITEM_NAME = "데이터베이스관리자권한을꼭필요한계정및그룹에대해서만허용"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검하여 관리자 권한의 남용을 방지하여 계정 유출로 인한 비인가자의 DB 접근 가능성을 최소화하고자함'
$threat = '관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하지 않으면 관리자 권한이 부여된 계정이 비인가자에게 유출될 경우 DB에 접근할 수 있는 위험이 존재함'
$criteria_good = '관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우'
$criteria_bad = '관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우'
$remediation = '관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여'

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
    # 1. sysadmin role members 확인
    $sysadminQuery = "EXEC sp_helpsrvrolemember 'sysadmin';"
    $sysadminResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $sysadminQuery -ErrorAction SilentlyContinue

    if ($sysadminResult) {
        $sysadminMembers = @()
        foreach ($member in $sysadminResult) {
            $memberName = $member.MemberPrincipalName
            if ($memberName -notmatch "^(sa|NT AUTHORITY|NT SERVICE|##MS_)") {
                $sysadminMembers += $memberName
                $vulnerabilities_found++
            }
        }

        if ($sysadminMembers.Count -gt 0) {
            $vulnerabilities += "sa 이외 sysadmin 권한 계정: $($sysadminMembers.Count)개"
            $resultDetails += "sysadmin 멤버 (제외 대상 제외): $($sysadminMembers -join ', ')"
        } else {
            $resultDetails += "sysadmin 권한: sa만 보유 (양호)"
        }
    }

    # 2. securityadmin role members 확인
    $securityadminQuery = "EXEC sp_helpsrvrolemember 'securityadmin';"
    $securityadminResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $securityadminQuery -ErrorAction SilentlyContinue

    if ($securityadminResult) {
        $securityadminMembers = @()
        foreach ($member in $securityadminResult) {
            $memberName = $member.MemberPrincipalName
            if ($memberName -notmatch "^(NT AUTHORITY|NT SERVICE|##MS_)") {
                $securityadminMembers += $memberName
            }
        }

        $resultDetails += "securityadmin 멤버 수: $($securityadminMembers.Count)"
    }

    # 3. server_principals에서 권한 확인
    $serverPrincipalsQuery = @"
SELECT name,
       type_desc,
       IS_SRVROLEMEMBER('sysadmin', name) as is_sysadmin,
       IS_SRVROLEMEMBER('securityadmin', name) as is_securityadmin,
       IS_SRVROLEMEMBER('db_accessadmin', name) as is_db_accessadmin,
       IS_SRVROLEMEMBER('db_securityadmin', name) as is_db_securityadmin
FROM sys.server_principals
WHERE type = 'S'
  AND name NOT IN ('sa', '##MS_Agent', '##MS_PolicyEventProcessor', '##MS_PolicySqlExecution', '##MS_PolicyStoredProcUpdates')
ORDER BY name;
"@

    $principalsResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $serverPrincipalsQuery -ErrorAction SilentlyContinue

    if ($principalsResult) {
        $adminCount = 0
        foreach ($principal in $principalsResult) {
            if ($principal.is_sysadmin -eq $true) {
                $adminCount++
            }
        }
        $resultDetails += "관리자 권한 계정 수: ${adminCount}개 (제외 대상 제외)"
    }

    # 4. CONTROL SERVER 권한 확인
    $controlServerQuery = @"
SELECT
    class_desc,
    permission_name,
    state_desc,
    grantee
FROM sys.server_permissions
WHERE permission_name = 'CONTROL SERVER'
  AND grantee NOT LIKE '##%';
"@

    $controlServerResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $controlServerQuery -ErrorAction SilentlyContinue

    if ($controlServerResult) {
        $controlServerUsers = @()
        foreach ($permission in $controlServerResult) {
            if ($permission.state_desc -eq "GRANT") {
                $grantee = $permission.grantee
                if ($grantee -notmatch "^(NT AUTHORITY|NT SERVICE|##MS_)") {
                    $controlServerUsers += $grantee
                    $vulnerabilities_found++
                }
            }
        }

        if ($controlServerUsers.Count -gt 0) {
            $vulnerabilities += "CONTROL SERVER 권한 계정: $($controlServerUsers -join ', ')"
            $resultDetails += "CONTROL SERVER 권한: $($controlServerUsers -join ', ')"
        }
    }

    # 5. 고위 권한 역할 목록
    $highPrivilegeRoles = @('sysadmin', 'securityadmin', 'serveradmin', 'setupadmin', 'processadmin', 'diskadmin', 'dbcreator', 'bulkadmin')
    $roleSummary = @()

    foreach ($role in $highPrivilegeRoles) {
        $roleQuery = "EXEC sp_helpsrvrolemember '$role';"
        $roleResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $roleQuery -ErrorAction SilentlyContinue

        if ($roleResult) {
            $memberCount = ($roleResult | Measure-Object).Count
            $roleSummary += "$role`: ${memberCount}명"
        }
    }

    if ($roleSummary.Count -gt 0) {
        $resultDetails += "고위 역할 할당 현황: " + ($roleSummary -join ", ")
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
    $inspection_summary = "불필요한 관리자 권한 부여 발견: " + ($vulnerabilities -join ", ")
}
else {
    $diagnosis_result = "GOOD"
    $status = "양호"
    $inspection_summary = "관리자 권한이 적절히 제한됨. " + ($resultDetails -join "; ")
}

$commandExecuted = "Invoke-Sqlcmd -ServerInstance $serverName -Database master -Query 'EXEC sp_helpsrvrolemember ''sysadmin'';'"

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
