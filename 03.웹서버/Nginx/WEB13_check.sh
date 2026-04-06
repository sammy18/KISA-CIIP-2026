#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-13
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 중
# @Title       : Nginx 디렉토리 리스팅(autoindex) 비활성화
# @Description : Nginx 웹 서버에서 디렉토리 리스팅 기능(autoindex)을 비활성화하여 디렉토리 내 파일 목록이 외부에 노출되지 않도록 합니다. autoindex off 설정으로 정보 유출을 방지해야 합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
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

ITEM_ID="WEB-13"
ITEM_NAME="Nginx 디렉토리 리스팅(autoindex) 비활성화"
SEVERITY="중"
GUIDELINE_PURPOSE="웹 서비스에서 DB 연결 파일에 대한 접근 권한 제한 및 불필요한 스크립트 매핑을 제거하여, DB 연결 정보(사용자 이름, 비밀번호 등)가 외부에 노출되거나 공격자의 DB 접근 및 관리자 권한 획득 등의 다양한공격을방지하기위함"
GUIDELINE_THREAT="웹서비스에서DB연결파일에대한접근권한제한및불필요한스크립트매핑을제거하지않을경우, DB 연결 파일에 존재하는 데이터베이스 관련 정보(IP주소, DB명, 비밀번호), 서버 내부 IP주소, 웹 서비스환경설정정보등보안상민감한내용이악의적인사용자에게노출될위험이존재함"
GUIDELINE_CRITERIA_GOOD="일반사용자의DB연결파일에대한접근을제한하고,불필요한스크립트매핑이제거된경우"
GUIDELINE_CRITERIA_BAD="일반사용자의DB연결파일에대한접근을제한하지않거나,불필요한스크립트매핑이제거되지 않은경우"
GUIDELINE_REMEDIATION="DB 연결 파일에 대한 접근 권한 제한 또는 불필요한 스크립트 매핑 제거 등을 통한 웹 서비스 내 DB 연결취약점제거설정"
diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"
    local diagnosis_result="VULNERABLE"
    local status="취약"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"; status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
    else
        local autoindex=$(grep -rhE "autoindex.*on" /etc/nginx/nginx.conf /etc/nginx/sites-enabled/ 2>/dev/null | grep -v "^\s*#" | head -1 || true)
        command_result="${autoindex}"
        command_executed="grep -rhE autoindex /etc/nginx/"
        if [ -n "${autoindex}" ]; then
            diagnosis_result="VULNERABLE"; status="취약"
            inspection_summary="autoindex on 설정이 발견되었습니다. 디렉토리 내 파일 목록이 노출됩니다. autoindex off;로 변경하세요."
        else
            diagnosis_result="GOOD"; status="양호"
            inspection_summary="autoindex가 off로 설정되어 있거나 on 설정이 없습니다. 디렉토리 리스팅이 비활성화되어 있습니다."
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
