#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-23
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : xp_cmdshell 확장 저장 프로시저 사용 제한
# @Description : xp_cmdshell 확장 저장 프로시저 사용 제한 관리를 통한 DBMS 보안 강화
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

ITEM_ID="D-23"
ITEM_NAME="xp_cmdshell 확장 저장 프로시저 사용 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요하게활성화되어있는xp_cmdshell를제한하여공격자의무단접근및악성코드의실행위험을 감소시키기위함"
GUIDELINE_THREAT="해킹툴에서자주이용되고있으며,권한상승이나데이터유출등의위험이존재함"
GUIDELINE_CRITERIA_GOOD="xp_cmdshell이비활성화되어있거나,활성화되어있으면다음의조건을모두만족하는경우 1. public의실행(Execute)권한이부여되어있지않은경우 2.서비스계정(애플리케이션연동)에sysadmin권한이부여되어있지않은경우"
GUIDELINE_CRITERIA_BAD="xp_cmdshell이활성화되어있고,양호의조건을만족하지않는경우"
GUIDELINE_REMEDIATION="xp_cmdshell 설정값을0또는False로설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="이 항목은 MSSQL 전용입니다. PostgreSQL에는 xp_cmdshell 기능이 없습니다."
    local command_result=""
    local command_executed=""

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
