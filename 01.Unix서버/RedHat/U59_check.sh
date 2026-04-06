#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-59
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 안전한 SNMP 버전 사용
# @Description : 취약한 SNMP v1, v2c 버전 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-59"
ITEM_NAME="안전한 SNMP 버전 사용"
SEVERITY="(중)"

GUIDELINE_PURPOSE="안전한SNMP버전사용으로전송되는데이터를보호하기위함"
GUIDELINE_THREAT="SNMP버전이기준보다낮을경우,응답패킷이평문으로전송되어스니핑위험이존재함"
GUIDELINE_CRITERIA_GOOD="SNMP서비스를v3이상으로사용하는경우"
GUIDELINE_CRITERIA_BAD="SNMP서비스를v2이하로사용하는경우"
GUIDELINE_REMEDIATION="Ÿ SNMP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ SNMP서비스사용시SNMP버전을v3이상으로적용하도록설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="SNMPv1/v2c 등 취약한 버전 설정이 발견되지 않았습니다."
    local command_result=""
    local command_executed="grep -Ei 'com2sec|community' /etc/snmp/snmpd.conf"

    if [ -f "/etc/snmp/snmpd.conf" ]; then
        local v12_check=$(grep -Ei "com2sec|community" /etc/snmp/snmpd.conf | grep -v "^#" | xargs || echo "")
        if [ -n "$v12_check" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="취약한 SNMPv1/v2c 커뮤니티 설정이 발견되었습니다."
            command_result="발견된 설정: [ ${v12_check} ]"
        fi
    fi
    command_result=$(echo "${command_result:-SNMP 설정 이상 없음}" | tr -d '\n\r')

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
