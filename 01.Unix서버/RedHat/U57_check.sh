#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-57
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat (Apache)
# @Severity    : (상)
# @Title       : Apache 웹 서비스 웹 프로세스 권한 제한
# @Description : 웹 서버의 자식 프로세스(Worker) 실행 권한이 root인지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-57"
ITEM_NAME="Apache 웹 서비스 웹 프로세스 권한 제한"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="root계정의FTP직접접속을제한하여root비밀번호정보노출을방지하기위함"
GUIDELINE_THREAT="FTP 서비스에 root 계정으로 접근할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 관리자계정및중요정보를외부로유출할위험이존재함"
GUIDELINE_CRITERIA_GOOD="root계정접속을차단한경우"
GUIDELINE_CRITERIA_BAD="root계정접속을허용한경우"
GUIDELINE_REMEDIATION="Ÿ FTP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ FTP서비스사용시root계정으로직접접속할수없도록설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="Apache 웹 프로세스 권한 설정(User, Group)이 적절합니다."
    local command_result=""
    local command_executed="grep -E '^User|^Group' /etc/httpd/conf/httpd.conf"

    # 1. 실제 데이터 추출
    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        local user_val=$(grep "^User" "$httpd_conf" | awk '{print $2}' | head -n 1 || echo "NotSet")
        local group_val=$(grep "^Group" "$httpd_conf" | awk '{print $2}' | head -n 1 || echo "NotSet")
        
        if [ "$user_val" = "root" ] || [ "$group_val" = "root" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="Apache 웹 프로세스가 root 권한으로 실행되도록 설정되어 있습니다."
        fi
        command_result="User: [ ${user_val} ], Group: [ ${group_val} ]"
    else
        command_result="Apache 설정 파일이 존재하지 않습니다."
    fi

    # [보정] JSON 파싱 에러 방지
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
