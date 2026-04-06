#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-44
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : tftp, talk 서비스 비활성화
# @Description : 인증 절차가 없는 tftp와 보안에 취약한 talk 서비스 비활성화 점검
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"; source "${LIB_DIR}/output_mode.sh"; source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-44"; ITEM_NAME="tftp, talk 서비스 비활성화"; SEVERITY="(상)"

GUIDELINE_PURPOSE="안전하지않거나불필요한서비스를제거함으로써시스템보안성및리소스의효율적운용하기위함"
GUIDELINE_THREAT="사용하지않는서비스나취약점이발표된서비스운용시공격시도가능한위험이존재함"
GUIDELINE_CRITERIA_GOOD="tftp, talk, ntalk서비스가비활성화된경우"
GUIDELINE_CRITERIA_BAD="tftp, talk, ntalk서비스가활성화된경우"
GUIDELINE_REMEDIATION="불필요한tftp, talk, ntalk서비스비활성화설정"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local inspection_summary="tftp 및 talk 서비스가 비활성화되어 있습니다."
    local command_result=""
    
    local active_svcs=$(grep -Ei "tftp|talk" /etc/xinetd.d/* 2>/dev/null | grep "disable" | grep -i "no" | awk -F: '{print $1}' | xargs || echo "")
    local proc_check=$(ps -ef | grep -Ei "tftpd|talkd" | grep -v grep || echo "")

    if [ -n "$active_svcs" ] || [ -n "$proc_check" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 tftp 또는 talk 서비스가 활성화되어 있습니다."
        command_result="활성 서비스/프로세스: [ ${active_svcs} ${proc_check} ]"
    else
        command_result="tftp, talk 서비스가 모두 비활성화되어 있습니다."
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "ls /etc/xinetd.d" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
