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
# @Platform    : MySQL
# @Severity    : 중
# @Title       : DBMS UPDATE 권한 점검
# @Description : UPDATE 권한을 제어하여 데이터 무단 수정 방지
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

GUIDELINE_PURPOSE="Audit Table 접근 권한을 관리자 계정으로 제한함으로써 비인가자가 감사 데이터의 수정, 삭제하는 것을 방지하고, 감사 기록 의무 결성과 신뢰성을 보장하기 위함"
GUIDELINE_THREAT="Audit Table이 데이터베이스 관리자 계정에 속하지 않을 경우, 비인가자가 감사 데이터의 수정, 삭제 등을 수행할 수 있으므로 보안 사고 발생 시 원인 분석이 불가능하게 되며, 이로 인해 재발 방지를 위한 조치를 할 수 없으므로 동일 유형의 공격이 반복되거나 시스템 취약점의 악용이 반복될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="AuditTable 접근 권한이 관리자 계정으로 설정한 경우"
GUIDELINE_CRITERIA_BAD="AuditTable 접근 권한이 일반 계정으로 설정한 경우"
GUIDELINE_REMEDIATION="AuditTable 접근 권한을 관리자 계정으로 제한"

# MySQL 연결 정보 초기화 (fallback if library not loaded)
DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_ADMIN_USER="${DB_ADMIN_USER:-${DB_USER}}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-${DB_PASSWORD}}"
diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # Initialize MySQL connection variables (only if library function exists)
    if declare -f init_mysql_vars >/dev/null 2>&1; then
        init_mysql_vars
    fi

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_mysql_tools >/dev/null 2>&1; then
        if ! check_mysql_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # MySQL/MariaDB 서비스 확인 (only if library function exists)
    if declare -f check_mysql_service >/dev/null 2>&1; then
        if ! check_mysql_service; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MySQL/MariaDB 서비스가 실행 중이지 않습니다. 서비스 시작 후 진단이 필요합니다."
            command_result="MySQL/MariaDB service not running"
            command_executed="mysqladmin ping -h ${DB_HOST} -P ${DB_PORT}"
            # Save results (only if library function exists)
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            if declare -f verify_result_saved >/dev/null 2>&1; then
                verify_result_saved "${ITEM_ID}"
            fi
            return 0
        fi
    fi

    # UPDATE 권한 확인
    local update_query="SELECT user, host FROM mysql.user WHERE Update_priv='Y' ORDER BY user, host;"
    command_executed="mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${update_query}\""
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${update_query}" 2>/dev/null || echo "")

    if [ -z "$command_result" ]; then
        # MySQL 8.0+의 경우
        command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "SELECT grantee, table_schema FROM information_schema.role_table_grants WHERE privilege_type='UPDATE' LIMIT 20;" 2>/dev/null || echo "")
    fi

    # 결과 분석
    if [ -n "$command_result" ]; then
        local update_count=$(echo "$command_result" | tail -n +2 | grep -v "^$" | wc -l)

        if [ "$update_count" -gt 0 ]; then
            local update_users=$(echo "$command_result" | tail -n +2 | grep -v "^$" || echo "")

            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="UPDATE 권한을 가진 계정 ${update_count}개 발견: $(echo "$update_users" | head -5 | tr '\n' ', ')"
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

    # Save results (only if library function exists)
    if declare -f save_dual_result >/dev/null 2>&1; then
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    fi
    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi

    return 0
}

main() {
    # MySQL 연결 확인 (FR-018) (only if library function exists)
    if declare -f check_mysql_connection >/dev/null 2>&1; then
        if ! check_mysql_connection; then
            diagnosis_result="MANUAL"
            status="수동진단"
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
                    "MySQL 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요" \
                    "연결 실패: User=${DB_USER}, Host=${DB_HOST}:${DB_PORT}" \
                    "mysql -u ${DB_USER} -h ${DB_HOST} -P ${DB_PORT}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 1
        fi
    fi

    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
