#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 중
# @Title       : SQL Server 인증 모드 점검
# @Description : SQL Server 인증 모드 점검 관리를 통한 DBMS 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

# Initialize MSSQL connection variables
init_mssql_vars

ITEM_ID="D-21"

ITEM_NAME="SQL Server 인증 모드 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="SQL Server의 인증 모드(Authentication Mode) 설정을 점검하여 잘 알려진 sa 계정을 이용한 계정 추측 공격의 위험을 방지하기 위함"
GUIDELINE_THREAT="SQL Server 및 Windows 인증 모드(혼합 모드)를 사용하고 sa 계정이 활성화되어 있는 경우, 비인가자가 잘 알려진 sa 계정에 대한 무차별 대입 공격 및 계정 추측 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Windows 인증 모드만 사용하도록 설정되어 있는 경우"
GUIDELINE_CRITERIA_BAD="SQL Server 및 Windows 인증 모드(혼합 모드)를 사용하도록 설정되어 있는 경우"
GUIDELINE_REMEDIATION="가능한 경우 Windows 인증 모드로 변경, 혼합 모드가 필요한 경우 sa 계정에 강력한 비밀번호 정책 적용"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="diagnosis_result="MANUAL" (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"DECLARE @AuthMode INT; EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', @AuthMode OUTPUT; SELECT @AuthMode AS LoginMode;\""
        inspection_summary="MSSQL 인증 모드 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. sqlcmd로 위 쿼리 실행\n"
        inspection_summary+="2. LoginMode = 1: 양호 (Windows 인증만)\n"
        inspection_summary+="3. LoginMode = 2: 취약 (혼합 모드: SQL+Windows)\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', REG_DWORD, 1;\n"
        inspection_summary+="-- 설정 후 SQL Server 서비스 재시작 필요"
    else
        inspection_summary="MSSQL 인증 모드 확인 - SQL Server Management Studio에서 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SSMS 실행 및 서버 우클릭 > Properties\n"
        inspection_summary+="2. Security 탭 확인\n"
        inspection_summary+="3. Server authentication:\n"
        inspection_summary+="   - Windows Authentication mode: 양호\n"
        inspection_summary+="   - SQL Server and Windows Authentication mode: 취약\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- SSMS: Server Properties > Security > Windows Authentication mode 선택\n"
        inspection_summary+="- T-SQL: EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', REG_DWORD, 1;\n"
        inspection_summary+="-- 설정 후 SQL Server 서비스 재시작 필요"
    fi

    diagnosis_result="MANUAL" status="수동진단"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
