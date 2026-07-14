#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-15
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : DBMS CREATE 권한 점검
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

ITEM_ID="D-15"
ITEM_NAME="DBMS CREATE 권한 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="일반 사용자에게 부여된 CREATE 권한(데이터베이스/테이블 생성 권한)을 점검하여 비인가자에 의한 무단 객체 생성으로 발생할 수 있는 자원 남용 및 보안 통제 우회를 방지하기 위함"
GUIDELINE_THREAT="일반 사용자에게 CREATE 권한이 부여된 경우, 비인가자가 임의로 데이터베이스나 테이블을 생성하여 자원을 고갈시키거나 은닉 채널로 악용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 계정 외 일반 사용자에게 CREATE 권한이 부여되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="관리자 계정 외 일반 사용자에게 CREATE 권한이 부여되어 있는 경우"
GUIDELINE_REMEDIATION="불필요한 일반 사용자 계정의 CREATE 권한 회수"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Initialize PostgreSQL connection variables
    init_postgresql_vars

    # PostgreSQL 서비스 확인
    if ! check_postgresql_service; then
        handle_dbms_not_running "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # PostgreSQL 연결 시도 (FR-018)
    if ! prompt_postgresql_connection; then
        handle_dbms_connection_failed "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local create_query="SELECT rolname FROM pg_roles WHERE rolcreatedb=true AND rolname!='postgres';"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -t -c \"${create_query}\""
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "${create_query}" 2>/dev/null || echo "")

    if [ -n "$command_result" ]; then
        local create_count=$(echo "$command_result" | grep -v "^$" | wc -l)

        if [ "$create_count" -gt 0 ]; then
            local create_users=$(echo "$command_result" | grep -v "^$" || echo "")

            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="CREATE 권한을 가진 ${create_count}개 계정 발견: $(echo "$create_users" | head -5 | tr '\n' ', ')"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="CREATE 권한을 가진 계정 없음"
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CREATE 권한 설정 양호"
    fi

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
