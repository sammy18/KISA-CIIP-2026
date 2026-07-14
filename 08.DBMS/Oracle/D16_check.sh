#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-16
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle
# @Severity    : 중
# @Title       : 비밀번호복잡성설정점검
# @Description : 비밀번호 복잡성 요구사항 강제로 약한 비밀번호 사용 방지 점검
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
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-16"

ITEM_NAME="비밀번호 복잡성 설정 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="비밀번호 복잡성 검증 함수(PASSWORD_VERIFY_FUNCTION)를 설정하여 문자/숫자/특수문자를 조합한 강력한 비밀번호 사용을 강제하고, 추측하기 쉬운 취약한 비밀번호 사용을 방지하기 위함"
GUIDELINE_THREAT="비밀번호 복잡성 검증 함수가 설정되어 있지 않거나 단순한 비밀번호(연속된 문자, 계정명과 동일한 비밀번호 등)를 허용하는 경우, 비인가자가 무차별 대입 공격 또는 사전 공격을 통해 계정 비밀번호를 탈취할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="프로파일에 PASSWORD_VERIFY_FUNCTION이 설정되어 있고, 최소 길이(8자 이상)와 영문 대소문자/숫자/특수문자 조합 등 복잡성 요건을 강제하는 경우"
GUIDELINE_CRITERIA_BAD="PASSWORD_VERIFY_FUNCTION이 설정되어 있지 않거나 NULL/DEFAULT로 되어 있어 비밀번호 복잡성 요건이 적용되지 않는 경우"
GUIDELINE_REMEDIATION="프로파일에 PASSWORD_VERIFY_FUNCTION을 설정하여 비밀번호 복잡성 요건(길이, 문자 조합)을 강제"

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_oracle_tools >/dev/null 2>&1; then
        if ! check_oracle_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    # Oracle 서비스 확인 (only if library function exists)
    if declare -f check_oracle_service >/dev/null 2>&1; then
        if ! check_oracle_service; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="Oracle 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            if declare -f verify_result_saved >/dev/null 2>&1; then
                verify_result_saved "${ITEM_ID}"
            fi
            return 0
        fi
    fi

    inspection_summary="Oracle 비밀번호 복잡성 함수 설정 확인 필요 (수동진단 권장)"
    diagnosis_result="MANUAL" status="수동진단"

    if declare -f save_dual_result >/dev/null 2>&1; then
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    fi
    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi
    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
