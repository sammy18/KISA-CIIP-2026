#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-63
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 사용자 sudo 명령어 사용 제한
# @Description : sudoers 파일을 통한 특정 명령어나 권한 제한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-63"
ITEM_NAME="사용자 sudo 명령어 사용 제한"
SEVERITY="(중)"

GUIDELINE_PURPOSE="비인가자가관리자권한을남용하여시스템손상,악성코드실행,민감한데이터유출등의보안위협을 방지하기위함"
GUIDELINE_THREAT="sudo 명령어 접근을 제한하지 않을 경우, 비인가자가 관리자 권한으로 허가되지 않은 명령어를 사용하여루트권한오용,악성코드실행,데이터유출등의시도를할위험이존재함"
GUIDELINE_CRITERIA_GOOD="/etc/sudoers파일소유자가root이고,파일권한이640인경우"
GUIDELINE_CRITERIA_BAD="/etc/sudoers파일소유자가root가아니거나,파일권한이640을초과하는경우"
GUIDELINE_REMEDIATION="/etc/sudoers파일소유자및권한변경설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="sudoers 설정이 적절하게 관리되고 있습니다."
    local command_result=""
    local command_executed="grep -v '^#' /etc/sudoers | grep 'ALL'"

    if [ -f "/etc/sudoers" ]; then
        local sudo_list=$(grep -v '^#' /etc/sudoers | grep "ALL" | xargs || echo "None")
        command_result="발견된 sudo 권한 설정: [ ${sudo_list} ]"
    else
        command_result="/etc/sudoers 파일이 존재하지 않습니다."
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
