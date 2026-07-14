#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : DBMS ALTER 권한 점검
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

ITEM_ID="D-14"
ITEM_NAME="DBMS ALTER 권한 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="일반 사용자에게 부여된 ALTER 권한을 점검하여 비인가자에 의한 테이블 구조 변경으로 발생할 수 있는 데이터 손상 및 서비스 장애를 방지하기 위함"
GUIDELINE_THREAT="일반 사용자에게 ALTER 권한이 부여된 경우, 비인가자가 테이블 구조(컬럼, 제약조건 등)를 임의로 변경하여 데이터 손상, 무결성 훼손, 애플리케이션 오류를 유발할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 계정 외 일반 사용자에게 ALTER 권한이 부여되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="관리자 계정 외 일반 사용자에게 ALTER 권한이 부여되어 있는 경우"
GUIDELINE_REMEDIATION="불필요한 일반 사용자 계정의 ALTER 권한 회수"

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

    # ALTER 권한 확인 (information_schema.table_privileges)
    local alter_query="SELECT grantee, table_schema, table_name FROM information_schema.role_table_grants WHERE privilege_type='ALTER' AND grantee NOT IN ('postgres', 'pg_signal_backend') LIMIT 20;"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"${alter_query}\""
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "${alter_query}" 2>/dev/null || echo "")

    # 결과 분석
    if [ -n "$command_result" ]; then
        local alter_count=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^grantee" | wc -l)

        if [ "$alter_count" -gt 0 ]; then
            local alter_users=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^grantee" || echo "")

            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="ALTER 권한을 가진 ${alter_count}개 그랜트 발견: $(echo "$alter_users" | head -3 | tr '\n' ', ')"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="ALTER 권한을 가진 계정 없음"
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="ALTER 권한 설정 양호"
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
