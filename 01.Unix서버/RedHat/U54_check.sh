#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-54
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat (Apache)
# @Severity    : (상)
# @Title       : Apache 불필요한 파일 제거
# @Description : 웹 서버 설치 시 기본적으로 생성되는 불필요한 파일(매뉴얼, 샘플 등) 제거 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-54"
ITEM_NAME="Apache 불필요한 파일 제거"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="암호화되지않은FTP서비스를비활성화함으로써계정및중요정보유출방지하기위함"
GUIDELINE_THREAT="암호화되지 않은 FTP 서비스를 사용할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 계정및중요정보를외부로유출할위험이존재함"
GUIDELINE_CRITERIA_GOOD="암호화되지않은FTP서비스가비활성화된경우"
GUIDELINE_CRITERIA_BAD="암호화되지않은FTP서비스가활성화된경우"
GUIDELINE_REMEDIATION="암호화되지않은FTP서비스중지및비활성화설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="Apache 불필요한 파일 및 디렉토리가 존재하지 않습니다."
    local command_result=""
    local command_executed="ls -d /var/www/html/manual /var/www/error"

    # 1. 실제 데이터 추출 (기본 경로 점검)
    local check_paths=("/var/www/html/manual" "/var/www/error" "/var/www/icons")
    local found_paths=""

    for path in "${check_paths[@]}"; do
        if [ -d "$path" ]; then
            found_paths+="${path} "
        fi
    done

    # 2. 판정 로직
    if [ -n "$found_paths" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="Apache 기본 매뉴얼 또는 에러 페이지 디렉토리가 존재합니다."
        command_result="발견된 경로: [ ${found_paths} ]"
    else
        command_result="불필요한 기본 파일이 발견되지 않았습니다."
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
