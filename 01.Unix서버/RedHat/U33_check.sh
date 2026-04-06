#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-33
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (하)
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 시스템 내 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-33"
ITEM_NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
SEVERITY="(하)"

GUIDELINE_PURPOSE="숨겨진파일및디렉토리중의심스러운내용은정상사용자가아닌공격자에의해생성되었을가능성이 높으므로이를제거하여보안위협을방지하기위함"
GUIDELINE_THREAT="숨겨진파일및디렉토리를방치할경우,비인가자가생성한악성파일또는백도어등을탐지하지못할 위험이존재함"
GUIDELINE_CRITERIA_GOOD="불필요하거나의심스러운숨겨진파일및디렉토리를제거한경우"
GUIDELINE_CRITERIA_BAD="불필요하거나의심스러운숨겨진파일및디렉토리를제거하지않은경우"
GUIDELINE_REMEDIATION="ls-al명령어로숨겨진파일존재파악후불법적이거나의심스러운파일을제거하도록설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="의심스러운 숨겨진 파일이 발견되지 않았습니다."
    local command_result=""
    local command_executed="find /tmp /var/tmp -name '.*' -type f"

    # 1. 파일 탐색 (정상적인 파일 몇 개는 제외하는 필터 추가 가능)
    local hidden_files
    hidden_files=$(find /tmp /var/tmp -name ".*" -type f 2>/dev/null | grep -vE ".X11-unix|.ICE-unix|.Test-unix" | head -n 10)

    if [ -n "$hidden_files" ]; then
        # 파일이 발견되면 수동 점검을 위해 '취약' 또는 '검토필요'로 변경
        status="취약" # KISA 가이드에 따라 일단 '발견' 시 취약으로 분류 후 소명
        diagnosis_result="VULNERABLE"
        inspection_summary="임시 디렉터리 내에 숨겨진 파일이 존재합니다. 악성 여부를 수동으로 확인하십시오."
        command_result=$(echo -e "발견된 숨김 파일 리스트:\n${hidden_files}")
    else
        command_result="임시 디렉토리 내에 숨겨진 파일이 없습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
