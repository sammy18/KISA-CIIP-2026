#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-19
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 상
# @Title       : SA 계정 비밀번호 점검
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

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

ITEM_ID="D-19"

ITEM_NAME="SA 계정 비밀번호 점검"
SEVERITY="상"

GUIDELINE_PURPOSE="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES의 설정을 점검하여 비인가자들의 데이터베이스 접근을 막고 데이터베이스 관리자에 의한 사용자 Role 설정이 가능하게하기 위함"
GUIDELINE_THREAT="OS_ROLES가 TRUE로 설정된 경우, 데이터베이스 접근 제어로 컨트롤되지 않는 OS 그룹에 의해 GRANT된 권한이 허락되어 악의적인 사용자가 시스템 권한을 악용할 위험이 존재 REMOTE_OS_ROLES가 TRUE로 설정된 경우, 원격 사용자가 OS의 다른 사용자로 속여 데이터베이스에 접근할 수 있으므로 중요 정보에 대한 무단 접근 및 권한 상승의 위험이 존재함 REMOTE_OS_AUTHENT가 TRUE로 설정된 경우, 신뢰하는 원격 호스트에서 인증 절차 없이 데이터베이스에 접속할 수 있으므로 중요 정보의 유출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우"
GUIDELINE_CRITERIA_BAD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 TRUE로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정을 FALSE로 변경"

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

    # MSSQL 서비스 확인 (Windows)
    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    # Linux 환경 sqlcmd 확인
    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT name, is_disabled FROM sys.server_principals WHERE name='sa';\""
        inspection_summary="MSSQL SA 계정 비밀번호 점검 - 수동 확인 필요\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. sqlcmd -S localhost -U sa -P 'password' (빈 비밀번호로 시도)\n"
        inspection_summary+="2. SELECT name, is_disabled FROM sys.server_principals WHERE name='sa'\n"
        inspection_summary+="3. SQL Server Management Studio에서 SA 계정 속성 확인\n\n"
        inspection_summary+="조치 방법: ALTER LOGIN sa WITH PASSWORD = 'Strong_P@ssw0rd';"
    else
        inspection_summary="MSSQL SA 계정 비밀번호 점검 - SQL Server Management Studio에서 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SSMS 실행 및 서버 연결\n"
        inspection_summary+="2. Security > Logins > sa 우클릭 > Properties\n"
        inspection_summary+="3. 비밀번호 강도 확인 (8자 이상, 대소문자/숫자/특수문자 혼합)\n\n"
        inspection_summary+="조치 방법: ALTER LOGIN sa WITH PASSWORD = 'Strong_P@ssw0rd';"
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
