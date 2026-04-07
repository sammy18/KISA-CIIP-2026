# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-24
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : Registry Procedure 권한 제한
# @Description : 레지스트리 관련 확장 저장 프로시저의 실행 권한 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-24"
$ITEM_NAME = "Registry Procedure 권한 제한"
$SEVERITY = "상"
$CATEGORY = "3.옵션관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '불필요한 RegistryProcedure의 권한 설정을 확인하고 제한하여 시스템의 보안 및 안정성을 강화하기 위함'
$threat = '불필요한 레지스트리 접근 권한이 제한되지 않는 경우, 공격자가 시스템을 변경하거나 악성 소프트웨어를 설치하여 권한 상승, 데이터 유출, 시스템 장애를 발생시킬 위험이 존재함'
$criteria_good = '제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여되지 않은 경우'
$criteria_bad = '제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여된 경우'
$remediation = 'guest/public에게 부여된 시스템 확장 저장 프로 시저 권한 제거'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
$resultDetails = @()
$nonAdminAccess = @()

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
    $diagnosis_result = "MANUAL"
    $status = "수동진단"
    $inspection_summary = "MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
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

if ($connectionSuccess) {
    # 1. 레지스트리 관련 프로시저 존재 확인
    $regProcedures = @('xp_regread', 'xp_regwrite', 'xp_regdeletekey', 'xp_regdeletevalue', 'xp_regenumvalues', 'xp_regenumkeys')

    try {
        $regProcList = $regProcedures -join "','"
        $procQuery = "SELECT name FROM sysobjects WHERE name IN ('$regProcList') AND xtype = 'X';"
        $procResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $procQuery -ErrorAction SilentlyContinue

        if ($procResult) {
            $resultDetails += "레지스트리 관련 확장 저장 프로시저:"
            foreach ($row in $procResult) {
                $resultDetails += "  - $($row.name)"
            }
        }
        else {
            $resultDetails += "레지스트리 관련 확장 저장 프로시저가 존재하지 않음"
        }
    }
    catch {
        $resultDetails += "레지스트리 프로시저 확인 실패: $($_.Exception.Message)"
    }

    # 2. 각 프로시저별 실행 권한 확인
    foreach ($procName in $regProcedures) {
        try {
            $permQuery = "EXEC sp_helprotect '$procName';"
            $permResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $permQuery -ErrorAction SilentlyContinue

            if ($permResult) {
                foreach ($row in $permResult) {
                    $grantee = $row.Grantee
                    if ($grantee -notin @('sysadmin', 'dbo', 'sa')) {
                        $nonAdminAccess += "$procName -> $grantee"
                        $resultDetails += "경고: $procName 실행 권한이 $grantee 에게 부여됨"
                    }
                }
            }
        }
        catch {
            # 권한 정보 없음 (정상)
        }
    }

    # 3. sysadmin 역할이 아닌 계정의 레지스트리 프로시저 권한 확인
    try {
        $directPermQuery = @"
SELECT dp.name AS UserName, obj.name AS ProcedureName
FROM sys.database_permissions pe
JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id
JOIN sys.objects obj ON pe.major_id = obj.object_id
WHERE obj.name LIKE 'xp_reg%'
  AND pe.permission_name = 'EXECUTE'
  AND dp.name NOT IN ('public')
"@
        $directPermResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $directPermQuery -ErrorAction SilentlyContinue

        if ($directPermResult) {
            foreach ($row in $directPermResult) {
                $userName = $row.UserName
                $procName2 = $row.ProcedureName
                $isAdminQuery = "SELECT IS_SRVROLEMEMBER('sysadmin', '$userName') AS IsAdmin;"
                $isAdminResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $isAdminQuery -ErrorAction SilentlyContinue
                if ($isAdminResult -and $isAdminResult.IsAdmin -ne 1) {
                    $nonAdminAccess += "$procName2 -> $userName (비관리자)"
                    $resultDetails += "경고: 비관리자 $userName 이(가) $procName2 실행 권한 보유"
                }
            }
        }
    }
    catch {
        $resultDetails += "직접 권한 확인 실패: $($_.Exception.Message)"
    }
}

# 최종 판정
if ($connectionSuccess) {
    if ($nonAdminAccess.Count -gt 0) {
        $diagnosis_result = "VULNERABLE"
        $status = "취약"
        $inspection_summary = "비관리자에게 레지스트리 프로시저 실행 권한이 부여됨:`r`n"
        $inspection_summary += ($nonAdminAccess -join "`r`n")
        $command_result = $resultDetails -join "`n"
    }
    else {
        $diagnosis_result = "GOOD"
        $status = "양호"
        $inspection_summary = "레지스트리 관련 확장 저장 프로시저가 적절히 제한됨"
        $command_result = if ($resultDetails.Count -gt 0) { $resultDetails -join "`n" } else { "비관리자의 레지스트리 프로시저 실행 권한 없음" }
    }
}
else {
    $inspection_summary = "SQL Server 연결 실패 - 수동 확인 필요`r`n`r`n"
    $inspection_summary += "검증 방법:`r`n"
    $inspection_summary += "1. 레지스트리 프로시저 존재 확인:`r`n"
    $inspection_summary += "   SELECT name FROM sysobjects WHERE name LIKE 'xp_reg%' AND xtype = 'X';`r`n`r`n"
    $inspection_summary += "2. 각 프로시저별 권한 확인:`r`n"
    $inspection_summary += "   EXEC sp_helprotect 'xp_regread';`r`n"
    $inspection_summary += "   EXEC sp_helprotect 'xp_regwrite';`r`n`r`n"
    $inspection_summary += "조치 방법:`r`n"
    $inspection_summary += "   REVOKE EXECUTE ON xp_regwrite FROM [계정];`r`n"
    $inspection_summary += "   REVOKE EXECUTE ON xp_regdeletekey FROM [계정];"
    $command_result = "연결 실패: Server=$serverName"
}

$commandExecuted = "SELECT name FROM sysobjects WHERE name LIKE 'xp_reg%' AND xtype = 'X';"

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
