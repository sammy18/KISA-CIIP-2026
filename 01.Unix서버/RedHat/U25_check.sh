#!/bin/bash
# ============================================================================
# @ID          : U-25
# @Title       : world writable 파일 점검
# ============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"

ITEM_ID="U-25"; ITEM_NAME="world writable 파일 점검"; SEVERITY="(상)"
GUIDELINE_PURPOSE="worldwritable파일을이용한시스템접근및악의적인코드실행을방지하기위함"
GUIDELINE_THREAT="시스템 파일과 같은 중요 파일에 world writable이 적용될 경우, 일반 사용자 및 비인가자가 해당 파일을임의로수정,제거할위험이존재함"
GUIDELINE_CRITERIA_GOOD="worldwritable파일이존재하지않거나,존재시설정이유를인지하고있는경우"
GUIDELINE_CRITERIA_BAD="worldwritable파일이존재하나설정이유를인지하지못하고있는경우"
GUIDELINE_REMEDIATION="worldwritable파일존재여부를확인하고불필요한경우제거하도록설정"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local command_result=""; local command_executed="find / -type f -perm -2 -xdev"

    # 시스템 내 world writable 파일 탐색 (최대 5개)
    local ww_files=$(find / -type f -perm -2 -xdev 2>/dev/null | head -n 5 | xargs)

    if [ -n "$ww_files" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        command_result="발견된 World Writable 파일(일부): [ $ww_files ]"
    else
        command_result="World Writable 파일 없음"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "점검 완료" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
