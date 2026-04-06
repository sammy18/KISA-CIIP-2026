#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-01
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : Default관리자계정명변경
# @Description : 웹서비스 설치 시 기본적으로 설정된 관리자 계정의 변경 후 사용 여부 점검
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

ITEM_ID="WEB-01"
ITEM_NAME="Default관리자계정명변경"
SEVERITY="상"

GUIDELINE_PURPOSE="기본 관리자 계정명과 같은 알려진 계정명을 유추하기 어려운 계정명으로 변경 후 사용하여 공격자에 의한추측공격및무단접근등을방지하고보안을강화하기위함"
GUIDELINE_THREAT="기본관리자계정명을변경하지않고사용할경우,공격자에의한계정및비밀번호추측공격이가능하고, 이를통해불법적인접근,데이터유출,시스템장애등의보안사고가발생할수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="관리자페이지를사용하지않거나,계정명이기본계정명으로설정되어있지않은경우"
GUIDELINE_CRITERIA_BAD="계정명이 기본 계정명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정명을 사용하는경우"
GUIDELINE_REMEDIATION="기본관리자계정명을추측하기어려운계정명으로설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary=""
    local command_result="N/A"
    local command_executed="N/A"

    # KISA 가이드라인 WEB-01 대상: Tomcat, JEUS only
    inspection_summary="WEB-01(Default관리자계정명변경) 항목의 KISA 가이드라인 점검 대상은 'Tomcat, JEUS'입니다. Nginx는 점검 대상이 아닙니다."

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
