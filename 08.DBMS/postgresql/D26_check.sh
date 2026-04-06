#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : DBMS 감사 로깅 점검
# @Description : 보안 감사 로그 기록 및 관리를 통한 추적성 확보
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

ITEM_ID="D-26"

ITEM_NAME="DBMS 감사 로깅 점검"
SEVERITY="중"
GUIDELINE_PURPOSE="데이터,로그,응용프로그램에대한감사기록정책을수립하고적용하여데이터베이스에문제발생시 원활하게대응하기위함"
GUIDELINE_THREAT="감사기록정책이설정되어있지않을경우,데이터베이스에문제발생시원인을규명할수있는자료가 존재하지않아이에대한대처및개선방안수립이어려워장기적으로심각한보안위험이존재함"
GUIDELINE_CRITERIA_GOOD="DBMS의감사로그저장정책이수립되어있으며,정책설정이적용된경우"
GUIDELINE_CRITERIA_BAD="DBMS에대한감사로그저장을하지않거나,정책설정이적용되지않은경우"
GUIDELINE_REMEDIATION="DBMS에대한감사로그저장정책수립,적용"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="PostgreSQL 감사 로깅 설정 확인 필요 (수동진단 권장)" command_result="" command_executed=""

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
