#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-14
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-14"
ITEM_NAME="root 홈, 패스 디렉터리 권한 및 패스 설정"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자가불법적으로생성한디렉터리및명령어를우선으로실행되지않도록설정하기위함"
GUIDELINE_THREAT="root 계정의 PATH 환경변수에 정상적인 관리자 명령어(ls, mv, cp 등)의 디렉터리 경로보다 현재 디렉터리를 지칭하는 '.' 표시가 우선하면 현재 디렉터리에 변조된 명령어를 삽입하여 관리자 명령어 입력시악의적인기능이실행될수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="PATH환경변수에'.'이맨앞이나중간에포함되지않은경우"
GUIDELINE_CRITERIA_BAD="PATH환경변수에'.'이맨앞이나중간에포함된경우"
GUIDELINE_REMEDIATION="root 계정의환경설정파일(/.profile, /.bashrc 등)과 시스템환경설정파일(/etc/profile등)에설정된 PATH환경변수에서현재디렉터리를나타내는'.'을PATH환경변수의마지막으로이동하도록설정 ※ /etc/profile파일,root계정,일반사용자계정의환경설정파일을순차적으로검색하여확인"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="PATH 설정이 적절합니다."
    local command_result=""
    local command_executed="echo \$PATH"

    # 1. 실제 데이터 추출
    local current_path=$PATH

    # 2. 판정 로직: 맨 앞(.) 또는 중간(:.:) 확인
    if [[ "$current_path" =~ ^\.: ]] || [[ "$current_path" =~ :\.: ]] || [[ "$current_path" =~ :: ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="PATH 환경변수에 '.' 이 맨 앞이나 중간에 포함되어 있습니다."
    fi

    # 3. command_result에 실제 PATH 전체 기록
    command_result="현재 PATH: [ ${current_path} ]"

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
