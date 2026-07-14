#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-13
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : DBMS INDEX 권한 점검
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

ITEM_ID="D-13"
ITEM_NAME="DBMS INDEX 권한 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="불필요한 데이터 소스 및 드라이버를 제거함으로써 비인가자에 의한 데이터베이스 접속 및 자료 유출을 차단하기 위함"
GUIDELINE_THREAT="불필요한 ODBC/OLE-DB 데이터 소스를 통한 비인가자의 데이터베이스 접속 및 주요 정보 유출에 대한 위험이 발생할 수 있음"
GUIDELINE_CRITERIA_GOOD="불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
GUIDELINE_CRITERIA_BAD="불필요한 ODBC/OLE-DB가 설치된 경우"
GUIDELINE_REMEDIATION="불필요한 ODBC/OLE-DB 제거"

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

    # PostgreSQL에서 INDEX 권한은 별도로 존재하지 않으며, CREATE 권한에 포함됨
    # 대신 객체 소유자와 권한을 확인
    local index_query="SELECT n.nspname AS schema, c.relname AS table, i.relname AS index, pg_get_userbyid(c.relowner) AS owner FROM pg_class i JOIN pg_index ix ON i.oid = ix.indexrelid JOIN pg_class c ON ix.indrelid = c.oid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE pg_get_userbyid(c.relowner) != 'postgres' LIMIT 20;"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"${index_query}\""
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "${index_query}" 2>/dev/null || echo "")

    # 결과 분석
    if [ -n "$command_result" ]; then
        local index_count=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^schema" | wc -l)

        if [ "$index_count" -gt 0 ]; then
            local index_users=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^schema" || echo "")

            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="postgres 외 사용자가 소유한 ${index_count}개 인덱스 발견: $(echo "$index_users" | head -3 | tr '\n' ', ')"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="postgres 계정에만 인덱스 소유권 부여됨"
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="INDEX 권한 설정 양호"
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
