#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-05
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : root 이외의 UID가 ‘0’ 금지
# @Description : root 계정 외에 UID 0을 사용하는 계정 존재 여부 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-05"
ITEM_NAME="root 이외의 UID가 ‘0’ 금지"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="root 계정과 동일한 UID가 존재하는지 점검하여 root 권한이 일반 사용자 계정이나 비인가자의 접근 위협에안전하게보호되고있는지확인하기위함"
GUIDELINE_THREAT="Ÿ root계정과동일한UID가설정되어있는일반사용자계정도root권한을부여받아관리자가실행할 수있는모든작업이가능한위험이존재함(서비스시작,중지,재부팅,root권한파일편집등) Ÿ root계정과동일한UID를사용하므로사용자감사추적시어려움발생위험이존재함"
GUIDELINE_CRITERIA_GOOD="root계정과동일한UID를갖는계정이존재하지않는경우"
GUIDELINE_CRITERIA_BAD="root계정과동일한UID를갖는계정이존재하는경우"
GUIDELINE_REMEDIATION="Ÿ UID가 0으로 설정된 계정을 0 이외의 중복되지 않은 UID로 변경 또는 불필요한 계정인 경우 제거하도록설정 Ÿ (사용중인계정인경우명령어를통한조치가적용되지않을수있으므로/etc/passwd파일을통해 변경)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="UID 0인 계정이 root만 존재합니다."
    local command_result=""
    local command_executed="awk -F: '\$3 == 0 {print \$1}' /etc/passwd"

    # 1. 실제 데이터 추출: UID 0 계정 리스트
    local uid_zero_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | xargs | sed 's/ /, /g')
    local user_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)

    # 2. 판정 로직
    if [ "$user_count" -gt 1 ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="root 이외에 UID 0을 사용하는 계정이 발견되었습니다."
    fi

    # 3. command_result에 실제 데이터 기록
    command_result="UID 0 계정 목록: [ ${uid_zero_users} ] (총 ${user_count}개)"

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
