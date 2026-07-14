#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : DBMS 백업/복구 권한 점검
# @Description : 과도한 권한 부여 방지 및 최소 권한 원칙 적용
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

ITEM_ID="D-25"

ITEM_NAME="DBMS 백업/복구 권한 점검"
SEVERITY="중"
GUIDELINE_PURPOSE="백업/복구 관련 권한이 관리자 계정으로 제한되어 있는지 점검하여 비인가자에 의한 백업 데이터 무단 접근 및 복구 기능 오남용을 방지하기 위함"
GUIDELINE_THREAT="일반 사용자에게 백업/복구 권한이 부여된 경우, 비인가자가 백업 파일을 통해 전체 데이터를 탈취하거나, 임의로 데이터를 복구(덮어쓰기)하여 데이터 무결성을 훼손할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="백업/복구 관련 권한이 관리자 계정으로만 제한되어 있는 경우"
GUIDELINE_CRITERIA_BAD="관리자 계정 외 일반 사용자에게 백업/복구 관련 권한이 부여되어 있는 경우"
GUIDELINE_REMEDIATION="불필요한 일반 사용자 계정의 백업/복구 관련 권한 회수"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="PostgreSQL 백업/복구 권한 확인 필요 (수동진단 권장)" command_result="" command_executed=""

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
