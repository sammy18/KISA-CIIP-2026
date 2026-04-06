#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-48
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : expn, vrfy 명령어 제한
# @Description : SMTP 서버의 EXPN 및 VRFY 명령어 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-48"
ITEM_NAME="expn, vrfy 명령어 제한"
SEVERITY="(중)"

GUIDELINE_PURPOSE="SMTP서비스의expn,vrfy명령을통한정보유출을방지하기위함"
GUIDELINE_THREAT="expn, vrfy 명령어를 통하여 특정 사용자 계정의 존재 여부를 알 수 있고, 사용자의 정보를 외부로 유출할수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="noexpn, novrfy옵션이설정된경우"
GUIDELINE_CRITERIA_BAD="noexpn, novrfy옵션이설정되어있지않은경우"
GUIDELINE_REMEDIATION="Ÿ 메일서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ 메일서비스사용시메일서비스설정파일에noexpn,novrfy또는goaway옵션추가설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="EXPN, VRFY 명령어 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep 'PrivacyOptions' /etc/mail/sendmail.cf"

    local cf_file="/etc/mail/sendmail.cf"
    if [ -f "$cf_file" ]; then
        local privacy_opts=$(grep "O PrivacyOptions" "$cf_file" | cut -d= -f2 || echo "")
        if [[ ! "$privacy_opts" =~ "noexpn" ]] || [[ ! "$privacy_opts" =~ "novrfy" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="PrivacyOptions 설정에서 noexpn 또는 novrfy 옵션이 누락되었습니다."
        fi
        command_result="PrivacyOptions 설정 값: [ ${privacy_opts} ]"
    else
        command_result="메일 설정 파일(/etc/mail/sendmail.cf)이 없습니다."
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
