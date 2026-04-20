# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-13
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 중
# @Title       : 불필요한ODBC/OLE-DB데이터소스와드라이브를제거하여사용
# @Description : 불필요한ODBC/OLE-DB데이터소스와드라이브를제거하여사용 관리를 통한 DBMS 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-13"
$ITEM_NAME = "불필요한ODBC/OLE-DB데이터소스와드라이브를제거하여사용"
$SEVERITY = "중"
$CATEGORY = "2.접근제어"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '불필요한 데이터 소스 및 드라이버를 제거함으로써 비인가자에 의한 데이터베이스 접속 및 자료 유출을 차단하기 위함'
$threat = '불필요한 ODBC/OLE-DB 데이터 소스를 통한 비인가자의 데이터베이스 접속 및 주요 정보 유출에 대한 위험이 발생할 수 있음'
$criteria_good = '불필요한 ODBC/OLE-DB가 설치되지 않은 경우'
$criteria_bad = '불필요한 ODBC/OLE-DB가 설치된 경우'
$remediation = '불필요한 ODBC/OLE-DB 제거'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
$resultDetails = @()

# ODBC 데이터소스 확인
try {
    # 시스템 DSN 확인
    $odbcRegPath = "HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources"
    if (Test-Path $odbcRegPath) {
        $systemDSNs = Get-Item -Path $odbcRegPath | Select-Object -ExpandProperty Property
        $resultDetails += "시스템 DSN 수: $($systemDSNs.Count)"
        foreach ($dsn in $systemDSNs) {
            $resultDetails += "  - $dsn"
        }
    }

    # 사용자 DSN 확인
    $userDsnRegPath = "HKCU:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources"
    if (Test-Path $userDsnRegPath) {
        $userDSNs = Get-Item -Path $userDsnRegPath | Select-Object -ExpandProperty Property
        $resultDetails += "사용자 DSN 수: $($userDSNs.Count)"
        foreach ($dsn in $userDSNs) {
            $resultDetails += "  - $dsn"
        }
    }
}
catch {
    $resultDetails += "ODBC 데이터소스 확인 실패: $($_.Exception.Message)"
}

$inspection_summary = "ODBC/OLE-DB 데이터소스 확인이 필요합니다.`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. ODBC 데이터소스 관리자 실행:`r`n"
$inspection_summary += "   - odbcad32.exe 실행 (시스템 DSN 탭)`r`n"
$inspection_summary += "2. 사용하지 않는 데이터소스 확인`r`n"
$inspection_summary += "   - 양호: 필요한 DSN만 존재`r`n"
$inspection_summary += "   - 취약: 불필요한 DSN 다수 존재`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "- 불필요한 DSN 삭제`r`n"
$inspection_summary += "- 사용하지 않는 ODBC 드라이버 제거`r`n`r`n"
$inspection_summary += "검증 결과:`r`n"
$inspection_summary += ($resultDetails -join "`r`n")

$commandExecuted = "Get-ChildItem HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC\ Data\ Sources"
$command_result = $resultDetails -join "`n"

$diagnosis_result = "MANUAL"
$status = "수동진단"

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
