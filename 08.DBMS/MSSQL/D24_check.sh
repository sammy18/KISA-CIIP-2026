#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-24
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 중
# @Title       : 레지스트리 접근 제한
# @Description : 레지스트리 접근용 확장 저장 프로시저 권한 제한 여부를 점검
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

# Initialize MSSQL connection variables
init_mssql_vars

ITEM_ID="D-24"

ITEM_NAME="레지스트리 접근 제한"
SEVERITY="중"
GUIDELINE_PURPOSE="불필요한 레지스트리 접근용 확장 저장 프로시저(xp_regread 등)의 권한 설정을 확인하고 제한하여 시스템의 보안 및 안정성을 강화하기 위함"
GUIDELINE_THREAT="레지스트리 접근 확장 저장 프로시저에 대한 실행 권한이 guest/public 등 비인가자에게 부여된 경우, 공격자가 이를 이용해 시스템 레지스트리를 변경하거나 악성 소프트웨어를 설치하여 권한 상승, 데이터 유출, 시스템 장애를 발생시킬 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="레지스트리 접근용 확장 저장 프로시저(xp_regread, xp_regwrite, xp_regdeletekey, xp_regdeletevalue, xp_regenumvalues, xp_regaddmultistring, xp_regremovemultistring)에 대한 실행 권한이 DBA(sysadmin) 외 guest/public에게 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="레지스트리 접근용 확장 저장 프로시저에 대한 실행 권한이 DBA 외 guest/public에게 부여된 경우"
GUIDELINE_REMEDIATION="guest/public 등 비인가 계정에 부여된 레지스트리 접근용 확장 저장 프로시저 실행 권한 회수 (예: REVOKE EXECUTE ON xp_regread TO public;)"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL"
    local status=""
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Check if MSSQL service is running
    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    fi

    # 레지스트리 접근용 확장 저장 프로시저에 대한 guest/public 실행 권한 점검
    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT pr.name AS proc_name, pe.state_desc, dp.name AS grantee FROM sys.database_permissions pe JOIN sys.objects pr ON pe.major_id = pr.object_id JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id WHERE pr.name IN ('xp_regread','xp_regwrite','xp_regdeletekey','xp_regdeletevalue','xp_regenumvalues','xp_regaddmultistring','xp_regremovemultistring') AND dp.name IN ('public','guest') AND pe.permission_name = 'EXECUTE' AND pe.state = 'G';\""
        command_result=$(sqlcmd -Q "SELECT pr.name AS proc_name, pe.state_desc, dp.name AS grantee FROM sys.database_permissions pe JOIN sys.objects pr ON pe.major_id = pr.object_id JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id WHERE pr.name IN ('xp_regread','xp_regwrite','xp_regdeletekey','xp_regdeletevalue','xp_regenumvalues','xp_regaddmultistring','xp_regremovemultistring') AND dp.name IN ('public','guest') AND pe.permission_name = 'EXECUTE' AND pe.state = 'G';" 2>/dev/null || echo "")

        if [ -n "${command_result}" ] && echo "${command_result}" | grep -qiE "xp_reg"; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="guest/public에게 레지스트리 접근용 확장 저장 프로시저 실행 권한이 부여되어 있습니다 (취약).\n\n"
            inspection_summary+="검증 결과:\n${command_result}\n\n"
            inspection_summary+="조치 방법:\n"
            inspection_summary+="REVOKE EXECUTE ON xp_regread TO public;\n"
            inspection_summary+="REVOKE EXECUTE ON xp_regwrite TO public;\n"
            inspection_summary+="-- 나머지 xp_reg* 프로시저도 동일하게 REVOKE 적용"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="guest/public에게 레지스트리 접근용 확장 저장 프로시저 실행 권한이 부여되어 있지 않습니다 (양호).\n\n"
            inspection_summary+="검증 결과: 해당 권한 없음"
        fi
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        command_executed="SSMS 또는 sqlcmd로 레지스트리 접근용 확장 저장 프로시저 권한 확인"
        inspection_summary="MSSQL 레지스트리 접근 확장 저장 프로시저(xp_regread 등) 권한 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SSMS 실행 > 서버 연결\n"
        inspection_summary+="2. 아래 쿼리로 guest/public 실행 권한 여부 확인:\n"
        inspection_summary+="   SELECT pr.name, dp.name AS grantee FROM sys.database_permissions pe\n"
        inspection_summary+="   JOIN sys.objects pr ON pe.major_id = pr.object_id\n"
        inspection_summary+="   JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id\n"
        inspection_summary+="   WHERE pr.name LIKE 'xp\\_reg%' ESCAPE '\\\\' AND dp.name IN ('public','guest');\n\n"
        inspection_summary+="조치 방법: REVOKE EXECUTE ON xp_regread TO public; (필요한 각 프로시저에 대해 반복)"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
