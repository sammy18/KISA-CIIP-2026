# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-03-31
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Windows)
# @Severity    : 중
# @Title       : 데이터베이스의주요설정파일,비밀번호파일등과같은주요파일들의접근권한이적절하게설정
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "D-14"
$ITEM_NAME = "데이터베이스의주요설정파일,비밀번호파일등과같은주요파일들의접근권한이적절하게설정"
$SEVERITY = "중"
$CATEGORY = "3.파일관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# GUIDELINE 정보
$purpose = '주요 파일들의 접근권한을 제한하여 무단 접근 및 데이터 유출 방지'
$threat = '주요 파일의 접근권한이 과도하게 열려있을 경우 민감정보 유출 위험'
$criteria_good = '주요 파일이 적절한 권한으로 보호된 경우'
$criteria_bad = '주요 파일에 과도한 접근 권한이 있는 경우'
$remediation = '파일 권한 변경 및 서비스 계정 외 제한'

# 변수 초기화
$diagnosis_result = "MANUAL"
$status = "수동진단"
$inspection_summary = ""
$command_result = ""
$commandExecuted = ""
$resultDetails = @()

# MSSQL 데이터 파일 권한 확인
try {
    # 기본 데이터 경로 확인
    $dataPath = Join-Path $env:ProgramFiles "Microsoft SQL Server\MSSQL\Data"

    if (Test-Path $dataPath) {
        $resultDetails += "MSSQL 데이터 경로: $dataPath"

        # mdf/ldf 파일 확인
        $dbFiles = Get-ChildItem -Path $dataPath -Filter "*.mdf" -ErrorAction SilentlyContinue
        if ($dbFiles) {
            foreach ($file in $dbFiles) {
                $acl = Get-Acl $file.FullName
                $owner = $acl.Owner
                $resultDetails += "$($file.Name): 소유자=$owner"
            }
        }
    }
}
catch {
    $resultDetails += "파일 권한 확인 실패: $($_.Exception.Message)"
}

$inspection_summary = "MSSQL 주요 파일 접근 권한 점검`r`n`r`n"
$inspection_summary += "검증 방법:`r`n"
$inspection_summary += "1. 데이터 파일 경로:`r`n"
$inspection_summary += "   - %PROGRAMFILES%\Microsoft SQL Server\MSSQL\Data\`r`n"
$inspection_summary += "2. 파일 권한 확인 (icacls 명령):`r`n"
$inspection_summary += "   icacls ""$env:ProgramFiles\Microsoft SQL Server\MSSQL\Data\*.mdf""`r`n`r`n"
$inspection_summary += "권장 권한:`r`n"
$inspection_summary += "- SQL Server 서비스 계정: 완전 제어`r`n"
$inspection_summary += "- 관리자: 완전 제어`r`n"
$inspection_summary += "- 기타 사용자: 권한 없음`r`n`r`n"
$inspection_summary += "조치 방법:`r`n"
$inspection_summary += "1. 파일 탐색기 > 파일 우클릭 > 속성 > 보안`r`n"
$inspection_summary += "2. SQL Server 서비스 계정 외 권한 제거`r`n"
$inspection_summary += "3. 상속 사용 안 함 > 명시적 권한만 부여`r`n`r`n"
$inspection_summary += "검증 결과:`r`n"
$inspection_summary += ($resultDetails -join "`r`n")

$commandExecuted = "Get-Acl ""$env:ProgramFiles\Microsoft SQL Server\MSSQL\Data\*.mdf"" | Format-List"
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
