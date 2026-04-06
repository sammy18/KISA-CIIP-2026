#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-17
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : DBMS UPDATE 권한 점검
# @Description : 과도한 권한 부여 방지 및 최소 권한 원칙 적용
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

ITEM_ID="D-17"
ITEM_NAME="DBMS UPDATE 권한 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="Audit Table 접근 권한을 관리자 계정으로 제한함으로써 비인가자가 감사 데이터의 수정, 삭제하는 것을방지하고,감사기록의무결성과신뢰성을보장하기위함"
GUIDELINE_THREAT="Audit Table이 데이터베이스 관리자 계정에 속하지 않을 경우, 비인가자가 감사 데이터의 수정, 삭제 등을수행할수있으므로보안사고발생시원인분석이불가능하게되며,이로인해재발방지를위한 조치를할수없으므로동일유형의공격이반복되거나시스템취약점의악용이반복될위험이존재함"
GUIDELINE_CRITERIA_GOOD="AuditTable접근권한이관리자계정으로설정한경우"
GUIDELINE_CRITERIA_BAD="AuditTable접근권한이일반계정으로설정한경우"
GUIDELINE_REMEDIATION="AuditTable접근권한을관리자계정으로제한"

# PostgreSQL 연결 정보 초기화
DB_ADMIN_USER="${DB_ADMIN_USER:-postgres}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

# PostgreSQL 연결 프롬프트 (FR-018)
check_postgresql_connection() {
    if [ -z "${DB_ADMIN_PASS}" ] && [ -t 0 ]; then
        echo "[INFO] PostgreSQL 연결 정보 입력이 필요합니다."
        read -p "PostgreSQL Host [${DB_HOST}]: " input_host
        DB_HOST="${input_host:-$DB_HOST}"

        read -p "PostgreSQL Port [${DB_PORT}]: " input_port
        DB_PORT="${input_port:-$DB_PORT}"

        read -p "PostgreSQL Username [${DB_ADMIN_USER}]: " input_user
        DB_ADMIN_USER="${input_user:-$DB_ADMIN_USER}"

        read -s -p "PostgreSQL Password: " input_pass
        echo ""
        DB_ADMIN_PASS="${input_pass}"
    fi

    # 3회 재시도 로직
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        # Try Unix socket connection first (peer authentication in Docker)
        if psql -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] PostgreSQL 연결 성공 (Unix socket)"
            export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
            return 0
        fi

        # Fall back to TCP connection with password
        if PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] PostgreSQL 연결 성공 (TCP)"
            export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
            return 0
        fi

        ((retry_count++)) || true
        if [ $retry_count -lt $max_retries ]; then
            echo "[WARN] PostgreSQL 연결 실패 (${retry_count}/${max_retries}). 2초 후 재시도..."
            sleep 2
        fi
    done

    return 1
}

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

    if ! pg_isready -h "${DB_HOST}" -p "${DB_PORT}" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="PostgreSQL 서비스 미실행"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    local update_query="SELECT grantee, table_schema FROM information_schema.role_table_grants WHERE privilege_type='UPDATE' AND grantee NOT IN ('postgres', 'pg_signal_backend') LIMIT 20;"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"${update_query}\""

    # Try Unix socket connection first (peer authentication in Docker)
    command_result=$(psql -U "${DB_ADMIN_USER}" -d postgres -c "${update_query}" 2>/dev/null || echo "")

    # Fall back to TCP connection with password
    if [ -z "$command_result" ]; then
        command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "${update_query}" 2>/dev/null || echo "")
    fi

    if [ -n "$command_result" ]; then
        local update_count=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^grantee" | wc -l)

        if [ "$update_count" -gt 0 ]; then
            local update_users=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^grantee" || echo "")

            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="UPDATE 권한을 가진 ${update_count}개 그랜트 발견: $(echo "$update_users" | head -3 | tr '\n' ', ')"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="UPDATE 권한을 가진 계정 없음"
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="UPDATE 권한 설정 양호"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    # PostgreSQL 연결 확인 (FR-018)
    if ! check_postgresql_connection; then
        diagnosis_result="MANUAL"
        status="수동진단"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "PostgreSQL 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요" \
            "연결 실패: User=${DB_ADMIN_USER}, Host=${DB_HOST}:${DB_PORT}" \
            "psql -U ${DB_ADMIN_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
