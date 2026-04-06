#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-50
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : DNS Zone Transfer 설정
# @Description : DNS 존 전송(Zone Transfer)을 제한하여 불필요한 영역 정보 노출을 방지하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-50"
ITEM_NAME="DNS Zone Transfer 설정"
SEVERITY="(상)"

GUIDELINE_PURPOSE="DNSZoneTransfer설정을통해비인가자에대한무단접근을방지하기위함"
GUIDELINE_THREAT="ZoneTransfer를모든사용자에게허용할경우,비인가자에게호스트정보,시스템정보등중요정보가 유출될위험이존재함"
GUIDELINE_CRITERIA_GOOD="ZoneTransfer를허가된사용자에게만허용한경우"
GUIDELINE_CRITERIA_BAD="Zone Transfer를모든사용자에게허용한경우"
GUIDELINE_REMEDIATION="Ÿ DNS서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ DNS서비스사용시DNSZoneTransfer를허가된사용자에게만전송허용하도록설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="DNS 존 전송 설정이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="grep 'allow-transfer' /etc/named.conf"

    if [ -f "/etc/named.conf" ]; then
        local transfer_opt=$(grep -i "allow-transfer" /etc/named.conf | tr -d '[:space:]' || echo "not-set")
        if [[ "$transfer_opt" == "not-set" ]] || [[ "$transfer_opt" =~ "any" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="DNS 존 전송이 제한되지 않았거나 모든 호스트(any)에 허용되어 있습니다."
        fi
        command_result="allow-transfer 설정 현황: [ ${transfer_opt} ]"
    else
        command_result="DNS 설정 파일(/etc/named.conf)이 존재하지 않습니다."
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
