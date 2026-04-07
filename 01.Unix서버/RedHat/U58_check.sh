#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-58
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 홈 디렉토리로 지정되지 않은 계정 금지
# @Description : 홈 디렉토리가 존재하지 않거나 잘못 지정된 계정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-58"
ITEM_NAME="홈 디렉토리로 지정되지 않은 계정 금지"
SEVERITY="(중)"

GUIDELINE_PURPOSE="불필요한 SNMP 서비스를 비활성화하여 필요 이상의 정보가 노출되는 것을 방지하기 위함"
GUIDELINE_THREAT="SNMP 서비스가 활성화되어 있을 경우, 비인가자가 시스템의 중요 정보를 유출하거나 불법적으로 수정할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스를 사용하지 않는 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스를 사용하는 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="모든 계정의 홈 디렉토리 설정이 적절합니다."
    local command_result=""
    local command_executed="awk -F: '\$6 == \"\" || \$6 == \"/\"' /etc/passwd"

    local invalid_users=$(awk -F: '$6 == "" || $6 == "/" {print $1}' /etc/passwd | xargs || echo "")
    if [ -n "$invalid_users" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="홈 디렉토리가 비어있거나 루트(/)로 지정된 계정이 발견되었습니다."
        command_result="대상 계정: [ ${invalid_users} ]"
    else
        command_result="모든 계정에 유효한 홈 디렉토리 경로가 지정되어 있습니다."
    fi

    command_result=$(echo "$command_result" | tr -d '\n\r')

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}
main "$@"
