#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-46
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 일반 사용자의 메일 서비스 실행 방지
# @Description : 일반 사용자가 메일 서비스를 임의로 실행하거나 제어하는 것을 방지하는 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-46"
ITEM_NAME="일반 사용자의 메일 서비스 실행 방지"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="일반 사용자의 q 옵션을 제한하여 메일 서비스 설정 및메일큐를강제적으로drop시킬수없게하여 비인가자에의한SMTP서비스오류방지하기위함"
GUIDELINE_THREAT="일반사용자가q옵션을이용해서메일큐,메일서비스설정을보거나메일큐를강제적으로drop시킬 수있어악의적으로SMTP서버의오류를발생시킬위험이존재함"
GUIDELINE_CRITERIA_GOOD="일반사용자의메일서비스실행방지가설정된경우"
GUIDELINE_CRITERIA_BAD="일반사용자의메일서비스실행방지가설정되어있지않은경우"
GUIDELINE_REMEDIATION="Ÿ 메일서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ 메일서비스사용시메일서비스의q옵션제한설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="일반 사용자의 메일 서비스 실행 방지 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -i 'PrivacyOptions' /etc/mail/sendmail.cf"

    # 1. 실제 데이터 추출 (Sendmail 기준)
    local cf_file="/etc/mail/sendmail.cf"
    if [ -f "$cf_file" ]; then
        local privacy_opts=$(grep -i "O PrivacyOptions" "$cf_file" | cut -d= -f2 || echo "")
        
        # 2. 판정 로직 (restrictmailq, restrictqrun 포함 여부 확인)
        if [[ ! "$privacy_opts" =~ "restrictmailq" ]] || [[ ! "$privacy_opts" =~ "restrictqrun" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="PrivacyOptions 설정에 일반 사용자 제한 옵션이 누락되어 있습니다."
        fi
        command_result="설정된 PrivacyOptions: [ ${privacy_opts:-설정 없음} ]"
    else
        command_result="Sendmail 설정 파일이 존재하지 않습니다."
    fi

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
