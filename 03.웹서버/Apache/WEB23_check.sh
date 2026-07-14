#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-23
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 중
# @Title       : HTTP 메서드 제한
# @Description : Apache 웹 서버에서 불필요한 HTTP 메서드를 제한하여 보안을 강화합니다. GET, POST, HEAD 등 필요한 메서드만 허용하고 PUT, DELETE 등의 위험한 메서드를 차단해야 합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -eu

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

ITEM_ID="WEB-23"
ITEM_NAME="HTTP 메서드 제한 (Apache)"
SEVERITY="중"
GUIDELINE_PURPOSE="LDAP 연결 시 안전한 비밀번호 다이제스트 알고리즘을 사용하여 비밀번호 평 문 전송 시 발생할 수 있는 스니핑 등의 공격에 대비하기 위함"
GUIDELINE_THREAT="취약한 다이제스트 알고리즘을 사용하는 경우 공격자의 스니핑, 무차별 공격 등을 통해 인증 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않는 경우"
GUIDELINE_REMEDIATION="LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"
    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary="Apache 서버의 HTTP 메서드 제한 설정을 수동으로 확인해야 합니다. 웹 서버 설정 파일에서 해당 헤더 또는 메서드 제한을 검토하세요."
    local command_result=""
    local command_executed=""
    
    if [ 23 -eq 23 ]; then
        # HTTP Methods restriction
        inspection_summary="HTTP 메서드 제한 설정을 확인하세요. Apache: LimitExcept, Nginx: limit_except, IIS: Request Filtering, Tomcat: security-constraint"
    elif [ 23 -eq 24 ]; then
        # X-Frame-Options
        inspection_summary="X-Frame-Options 헤더 설정을 확인하세요. Apache: Header always set X-Frame-Options DENY, Nginx: add_header X-Frame-Options DENY"
    elif [ 23 -eq 25 ]; then
        # X-XSS-Protection
        inspection_summary="X-XSS-Protection 헤더 설정을 확인하세요. Apache/Nginx: add_header X-XSS-Protection '1; mode=block'"
    elif [ 23 -eq 26 ]; then
        # X-Content-Type-Options
        inspection_summary="X-Content-Type-Options 헤더 설정을 확인하세요. Apache/Nginx: add_header X-Content-Type-Options nosniff"
    fi
    
    # Run-all 모드 확인
    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    # 결과 저장 확인
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
