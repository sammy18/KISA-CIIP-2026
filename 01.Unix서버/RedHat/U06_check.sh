#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-06
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 사용자 계정 su 기능 제한
# @Description : 특정 그룹에 속한 사용자만 su 명령어를 사용할 수 있도록 제한하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-06"
ITEM_NAME="사용자 계정 su 기능 제한"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="su 관련 그룹만 su 명령어 사용 권한이 부여되어 있는지 점검하여 su 그룹에 포함되지 않은 일반 사용자의su명령사용을원천적으로차단하는지확인하기위함"
GUIDELINE_THREAT="무분별한 사용자 변경으로 타 사용자 소유의 파일을 변경할 수 있으며 root 계정으로 변경하는 경우 관리자권한을획득할수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="su명령어를특정그룹에속한사용자만사용하도록제한된경우 ※일반사용자계정없이root계정만사용하는경우su명령어사용제한불필요"
GUIDELINE_CRITERIA_BAD="su명령어를모든사용자가사용하도록설정된경우"
GUIDELINE_REMEDIATION="PAM모듈설정또는su명령어허용그룹생성후su명령어일반사용자권한제거하도록설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="su 기능 제한 설정이 적절히 적용되어 있습니다."
    local command_result=""
    local command_executed="grep 'pam_wheel.so' /etc/pam.d/su && grep 'wheel' /etc/group"

    # 1. 실제 데이터 추출: PAM 설정 및 그룹 멤버 확인
    local pam_check=$(grep "pam_wheel.so" /etc/pam.d/su | grep -v "^#" || echo "미설정")
    local wheel_users=$(grep "^wheel:" /etc/group | cut -d: -f4)

    # 2. 판정 로직
    if [ "$pam_check" = "미설정" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="su 명령어 사용 제한(pam_wheel.so)이 설정되어 있지 않습니다."
    fi

    # 3. command_result에 실제 데이터 기록
    command_result="PAM 설정: [ ${pam_check} ] | wheel 그룹 멤버: [ ${wheel_users:-없음} ]"

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
