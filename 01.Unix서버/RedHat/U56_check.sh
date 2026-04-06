#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-56
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat (Apache)
# @Severity    : (중)
# @Title       : Apache 파일 업로드 및 다운로드 제한
# @Description : 웹 서버의 파일 업로드 용량 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-56"
ITEM_NAME="Apache 파일 업로드 및 다운로드 제한"
SEVERITY="(중)"

# 가이드라인 정보
GUIDELINE_PURPOSE="접근권한이없는비인가자의접근을통제하기위함"
GUIDELINE_THREAT="FTP 서비스의 접근제한 설정이 적절하지 않을 경우, 인증 절차 없이 비인가자가 디렉터리나 파일에 접근할수있어중요파일변조및유출을시도할위험이존재함"
GUIDELINE_CRITERIA_GOOD="특정IP주소또는호스트에서만FTP서버에접속할수있도록접근제어설정을적용한경우 취약:FTP서버에접근제어설정을적용하지않은경우"
GUIDELINE_CRITERIA_BAD="업로드 용량 제한 설정이 되어 있지 않거나 너무 크게 설정된 경우"
GUIDELINE_REMEDIATION="Ÿ FTP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ FTP서비스사용시접근제어설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="파일 업로드 제한(LimitRequestBody) 설정이 존재합니다."
    local command_result=""
    local command_executed="grep -r 'LimitRequestBody' /etc/httpd/conf*"

    # 1. 실제 데이터 추출
    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        local limit_size=$(grep -i "LimitRequestBody" "$httpd_conf" | awk '{print $2}' | head -n 1 || echo "NotSet")
        
        if [ "$limit_size" = "NotSet" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="LimitRequestBody 설정이 되어 있지 않습니다."
        fi
        command_result="설정된 업로드 제한 크기: [ ${limit_size} ] (Bytes)"
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
