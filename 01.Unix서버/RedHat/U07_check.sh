#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-07
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (하)
# @Title       : 불필요한 계정 제거
# @Description : 시스템 계정 중 불필요한 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-07"
ITEM_NAME="불필요한 계정 제거"
SEVERITY="(하)"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한계정이존재하는지점검하여관리되지않은계정에의한침입에대비하는지확인하기위함"
GUIDELINE_THREAT="로그인이 가능하고 현재 사용하지 않는 불필요한 계정은 사용 중인 계정보다 상대적으로 관리가 취약하여공격자의목표가되어계정이탈취될수있는위험이존재함(퇴직, 전직, 휴직 등의 사유 발생 시즉시권한을회수하는것을권고함)"
GUIDELINE_CRITERIA_GOOD="불필요한계정이존재하지않는경우"
GUIDELINE_CRITERIA_BAD="불필요한계정이존재하는경우"
GUIDELINE_REMEDIATION="시스템에존재하는계정확인후불필요한계정제거하도록설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="불필요한 계정이 발견되지 않았습니다."
    local command_result=""
    local command_executed="grep -E 'lp|uucp|nuucp' /etc/passwd"

    # 1. 실제 데이터 추출: 이미지 가이드에 명시된 기본 계정(lp, uucp, nuucp 등) 확인
    local target_accounts=("lp" "uucp" "nuucp")
    local found_list=""
    
    for account in "${target_accounts[@]}"; do
        if grep -q "^${account}:" /etc/passwd; then
            found_list+="${account} "
        fi
    done

    # 2. 판정 로직
    if [ -n "$found_list" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="시스템에 불필요한 계정이 존재합니다."
    fi

    # 3. command_result에 실제 발견된 계정명을 데이터 증적으로 기록
    command_result="발견된 불필요 계정: [ ${found_list:-없음} ]"

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
