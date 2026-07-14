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
# @Platform    : MySQL
# @Severity    : 중
# @Title       : DBMS INDEX 권한 점검
# @Description : INDEX 권한을 제어하여 인덱스 조작으로 인한 성능 저하 방지
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

    # INDEX 권한 확인 (mysql.user 테이블의 Index_priv는 MySQL 8.0에서 제거됨)
    local index_query="SELECT user, host FROM mysql.user WHERE Index_priv='Y' ORDER BY user, host;"
    command_executed="mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${index_query}\""
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${index_query}" 2>/dev/null || echo "")

    if [ -z "$command_result" ]; then
        # MySQL 8.0+의 경우
        command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "SELECT grantee, table_schema FROM information_schema.role_table_grants WHERE privilege_type='INDEX' LIMIT 20;" 2>/dev/null || echo "")
    fi

    # 결과 분석
    if [ -n "$command_result" ]; then
        local index_count=$(echo "$command_result" | tail -n +2 | grep -v "^$" | wc -l)

        if [ "$index_count" -gt 0 ]; then
            local index_users=$(echo "$command_result" | tail -n +2 | grep -v "^$" || echo "")
            local non_root_index=$(echo "$index_users" | grep -v -E "^root\s" || echo "")

            if [ -n "$non_root_index" ]; then
                diagnosis_result="VULNERABLE"
                status="취약"
                inspection_summary="비-root 계정에 INDEX 권한 부여됨: $(echo "$non_root_index" | head -5 | tr '\n' ', ')"
            else
                diagnosis_result="GOOD"
                status="양호"
                inspection_summary="root 계정에만 INDEX 권한 부여됨 (총 ${index_count}개)"
            fi
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="INDEX 권한을 가진 계정 없음"
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="INDEX 권한 설정 양호"
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
