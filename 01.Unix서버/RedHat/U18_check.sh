#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-18
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일의 소유자 및 권한 설정이 적절한지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-18"
ITEM_NAME="/etc/shadow 파일 소유자 및 권한 설정"
SEVERITY="(상)"

# 가이드라인 정보 (PDF 43페이지 내용 반영)
GUIDELINE_PURPOSE="/etc/shadow파일을관리자만제어할수있게하여비인가자들의임의적인파일변조를방지하기위함"
GUIDELINE_THREAT="/etc/shadow파일에저장된암호화된해시값을복호화하여(크래킹)비밀번호를탈취할위험이존재함"
GUIDELINE_CRITERIA_GOOD="/etc/shadow파일의소유자가root이고,권한이400이하인경우"
GUIDELINE_CRITERIA_BAD="/etc/shadow파일의소유자가root가아니거나,권한이400이하가아닌경우"
GUIDELINE_REMEDIATION="/etc/shadow파일소유자및권한변경설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="/etc/shadow 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/shadow"

    local file_path="/etc/shadow"
    if [ -f "$file_path" ]; then
        local owner_name=$(stat -c "%U" "$file_path")
        local file_perm=$(stat -c "%a" "$file_path")
        local ls_out=$(ls -l "$file_path")

        if [ "$owner_name" != "root" ] || [ "$file_perm" -gt 400 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="/etc/shadow 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        command_result="/etc/shadow 파일이 존재하지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && exit 1
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
}

main "$@"
