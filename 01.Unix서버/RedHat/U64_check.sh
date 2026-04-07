#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-64
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : r-command 서비스 비활성화
# @Description : rlogin, rsh, rexec 등 취약한 r-command 서비스 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-64"
ITEM_NAME="r-command 서비스 비활성화"
SEVERITY="(상)"

GUIDELINE_PURPOSE="주기적인 패치 적용을 통해 시스템 안정성 및 보안성을 확보하기 위함"
GUIDELINE_THREAT="최신 보안 패치가 적용되지 않을 경우, 이미 알려진 취약점을 통하여 공격자에 의해 시스템 침해 사고 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우"
GUIDELINE_CRITERIA_BAD="패치 적용 정책이 미수립되었거나 주기적으로 패치 관리를 하지 않는 경우"
GUIDELINE_REMEDIATION="OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용하도록 설정 ※ OS 패치의 경우 지속해서 취약점이 발표되고 있으므로 O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책을 수립하여 적용해야함"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="취약한 r-command 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ls -l /etc/xinetd.d/r*"

    local r_services=$(ls /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec 2>/dev/null || echo "")
    if [ -n "$r_services" ]; then
        local active_r=$(grep -i "disable" $r_services | grep "no" || echo "")
        if [ -n "$active_r" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="r-command 서비스가 xinetd에서 활성화되어 있습니다."
            command_result="활성화된 서비스: [ $(echo $active_r | xargs) ]"
        fi
    fi
    command_result=$(echo "${command_result:-r-command 미발견}" | tr -d '\n\r')

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
