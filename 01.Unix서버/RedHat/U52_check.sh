#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-52
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat (Apache)
# @Severity    : (중)
# @Title       : Apache HTTPD 버전 정보 숨김
# @Description : ServerTokens 및 ServerSignature 설정을 통한 버전 정보 노출 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-52"
ITEM_NAME="Apache HTTPD 버전 정보 숨김"
SEVERITY="(중)"

GUIDELINE_PURPOSE="취약한Telnet프로토콜을비활성화함으로써계정및중요정보유출방지하기위함"
GUIDELINE_THREAT="원격접속시Telnet 프로토콜을 사용할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 계정및중요정보를외부로유출할위험이존재함"
GUIDELINE_CRITERIA_GOOD="원격접속시Telnet프로토콜을비활성화하고있는경우"
GUIDELINE_CRITERIA_BAD="원격접속시Telnet프로토콜을사용하는경우"
GUIDELINE_REMEDIATION="Telnet,FTP등안전하지않은서비스사용을중지하고SSH설치및사용하도록설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="Apache 버전 정보 숨김 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -E 'ServerTokens|ServerSignature' /etc/httpd/conf/httpd.conf"

    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        local tokens=$(grep -v '^#' "$httpd_conf" | grep -i "ServerTokens" | awk '{print $2}' || echo "NotSet")
        local signature=$(grep -v '^#' "$httpd_conf" | grep -i "ServerSignature" | awk '{print $2}' || echo "NotSet")
        
        if [[ "$tokens" != "Prod" ]] || [[ "$signature" != "Off" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="ServerTokens(Prod) 또는 ServerSignature(Off) 설정이 부적절합니다."
        fi
        command_result="ServerTokens: ${tokens}, ServerSignature: ${signature}"
    else
        command_result="Apache 설정 파일이 존재하지 않습니다."
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
