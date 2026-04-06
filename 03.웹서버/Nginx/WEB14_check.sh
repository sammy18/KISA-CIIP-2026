#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-14
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : Nginx default server block 설정
# @Description : Nginx default server block 설정 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="WEB-14"
ITEM_NAME="Nginx default server block 설정"
SEVERITY="하"

GUIDELINE_PURPOSE="웹 서비스 경로의 파일들에 관리자를 제외한 일반 사용자의 파일 접근 권한을 제거함으로써 인가되지 않은사용자가허용되지않는파일에접근하는것을차단하기위함"
GUIDELINE_THREAT="웹서비스경로파일에비인가자가접근가능한경우,해당파일의수정및삭제로인해웹서비스운영 장애및계정비밀번호정보등의중요한정보가노출될위험이존재함"
GUIDELINE_CRITERIA_GOOD="주요설정파일및디렉터리에불필요한접근권한이부여되지않은경우"
GUIDELINE_CRITERIA_BAD="주요설정파일및디렉터리에불필요한접근권한이부여된경우"
GUIDELINE_REMEDIATION="주요설정파일및디렉터리에불필요한접근권한제거설정"
diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"; status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
    else
        local def_srv=$(grep -rhE "default_server" /etc/nginx/ 2>/dev/null | grep -v "^\s*#" | head -3 || true)
        command_result="${def_srv}"
        command_executed="grep -rhE default_server /etc/nginx/"
        if [ -n "${def_srv}" ]; then
            diagnosis_result="GOOD"; status="양호"
            inspection_summary="default_server 설정이 발견되었습니다. 기본 server block이 명시적으로 설정되어 있습니다."
        else
            diagnosis_result="GOOD"; status="양호"
            inspection_summary="default_server 설정이 없습니다. 명시적인 default_server 설정을 권장합니다."
        fi
    fi
    # Run-all 모드 확인
    # 결과 저장 (run_all 모드는 라이브러리에서 판단)
    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"
    return 0
}
main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}
if true; then
    main "$@"
fi
