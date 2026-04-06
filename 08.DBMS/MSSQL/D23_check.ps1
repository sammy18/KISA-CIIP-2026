# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-23
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 상
# @Title       : xp_cmdshell 사용 제한
# @Description : xp_cmdshell 확장 저장 프로시저 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-23"
$ITEM_NAME = "xp_cmdshell 사용 제한"
$SEVERITY = "상"
$CATEGORY = "3.옵션관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = 'xp_cmdshell 확장 저장 프로시저를 비활성화하여 운영체제 명령어 실행을 통한 시스템 침해를 방지하기 위함'
$threat = 'xp_cmdshell이 활성화된 경우 SQL Injection 등을 통해 공격자가 운영체제 명령어를 실행할 수 있어 시스템 전체가 위험에 노출됨'
$criteria_good = 'xp_cmdshell이 비활성화되어 있는 경우'
$criteria_bad = 'xp_cmdshell이 활성화되어 있는 경우'
$remediation = 'EXEC sp_configure ''xp_cmdshell'', 0; RECONFIGURE;'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
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
    # 1. xp_cmdshell 활성화 상태 확인
    try {
        $configQuery = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell';"
        $configResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $configQuery -ErrorAction SilentlyContinue

        if ($configResult) {
            $runValue = $configResult.run_value
            $configValue = $configResult.config_value
            $resultDetails += "xp_cmdshell run_value: $runValue"
            $resultDetails += "xp_cmdshell config_value: $configValue"

            if ($runValue -eq 1) {
                $resultDetails += "xp_cmdshell이 활성화되어 있음 (취약)"
                $diagnosis_result = "VULNERABLE"
                $status = "취약"
            }
            else {
                $resultDetails += "xp_cmdshell이 비활성화되어 있음 (양호)"
                $diagnosis_result = "GOOD"
                $status = "양호"
            }
        }
    }
    catch {
        $resultDetails += "xp_cmdshell 설정 확인 실패: $($_.Exception.Message)"
    }

    # 2. xp_cmdshell 실행 권한 확인
    try {
        $permQuery = @"
SELECT dp.name AS UserName, dp.type_desc AS UserType
FROM sys.database_permissions pe
JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id
JOIN sys.objects obj ON pe.major_id = obj.object_id
WHERE obj.name = 'xp_cmdshell'
  AND pe.permission_name = 'EXECUTE'
  AND dp.name NOT IN ('public')
"@
        $permResult = Invoke-Sqlcmd -ServerInstance $serverName -Database "master" -Query $permQuery -ErrorAction SilentlyContinue

        if ($permResult) {
            $resultDetails += "xp_cmdshell 실행 권한 계정:"
            foreach ($row in $permResult) {
                $resultDetails += "  - $($row.UserName) ($($row.UserType))"
            }
        }
    }
    catch {
        $resultDetails += "xp_cmdshell 권한 확인 실패: $($_.Exception.Message)"
    }
}

# 최종 판정
if ($diagnosis_result -eq "MANUAL") {
    if (-not $connectionSuccess) {
        $inspection_summary = "SQL Server 연결 실패 - 수동 확인 필요`r`n`r`n"
        $inspection_summary += "검증 방법:`r`n"
        $inspection_summary += "1. SSMS에서 새 쿼리 실행:`r`n"
        $inspection_summary += "   EXEC sp_configure 'show advanced options', 1; RECONFIGURE;`r`n"
        $inspection_summary += "   EXEC sp_configure 'xp_cmdshell';`r`n"
        $inspection_summary += "2. run_value가 0이면 양호, 1이면 취약`r`n`r`n"
        $inspection_summary += "조치 방법:`r`n"
        $inspection_summary += "   EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
        $command_result = "연결 실패: Server=$serverName"
    }
}
else {
    $inspection_summary = "MSSQL xp_cmdshell 사용 제한 점검`r`n`r`n"
    $inspection_summary += "검증 결과:`r`n"
    $inspection_summary += ($resultDetails -join "`r`n")
    $command_result = $resultDetails -join "`n"
}

$commandExecuted = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell';"

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
