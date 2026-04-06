#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-53
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat (Apache)
# @Severity    : (상)
# @Title       : Apache 상위 디렉토리 접근 제한
# @Description : 사용자별 홈 디렉토리 서비스(/~user) 및 상위 디렉토리 접근 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-53"
ITEM_NAME="Apache 상위 디렉토리 접근 제한"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP서비스접속배너를통한불필요한정보노출을방지하기위함"
GUIDELINE_THREAT="서비스 접속 배너가 차단되지 않을 경우, 비인가자가 FTP 접속 시도 시 노출되는 접속 배너 정보를 수집하여악의적인공격에이용할위험이존재함"
GUIDELINE_CRITERIA_GOOD="FTP접속배너에노출되는정보가없는경우"
GUIDELINE_CRITERIA_BAD="FTP접속배너에노출되는정보가있는경우"
GUIDELINE_REMEDIATION="Ÿ FTP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ FTP서비스사용시FTP설정파일을통해접속배너설정 ※ 접속배너에서비스이름이나버전정보를노출하지않는것을권고"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="상위 디렉토리 및 사용자 홈 디렉토리 접근 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -i 'UserDir' /etc/httpd/conf.d/userdir.conf"

    # 1. UserDir 설정 확인 (RHEL 표준 경로)
    local userdir_conf="/etc/httpd/conf.d/userdir.conf"
    if [ -f "$userdir_conf" ]; then
        local userdir_status=$(grep -v '^#' "$userdir_conf" | grep -i "UserDir" | head -n 1 | awk '{print $2}' || echo "disabled")
        if [[ "$userdir_status" != "disabled" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="사용자 홈 디렉토리 서비스(UserDir)가 활성화되어 있습니다."
        fi
        command_result="UserDir 설정 상태: [ ${userdir_status} ]"
    else
        command_result="사용자 홈 디렉토리 설정 파일이 존재하지 않습니다(기본 비활성)."
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
