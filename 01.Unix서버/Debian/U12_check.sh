#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-12
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 하
# @Title       : 세션 종료시간 설정
# @Description : TMOUT 또는 /etc/profile 설정 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

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


ITEM_ID="U-12"
ITEM_NAME="세션 종료시간 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의 고의 또는 실수로 시스템에 계정이 접속된 상태로 방치됨을 차단하기 위함"
GUIDELINE_THREAT="Sessiontimeout 값이 설정되지 않을 경우, 유휴 시간 내 비인가자가 시스템에 접근하여 불필요한 내부 정보를 노출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Session Timeout이 600초(10분)이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="Session Timeout이 600초(10분)이하로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="600초(10분)동안 입력이 없는 경우 접속된 Session을 끊도록 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # 세션 종료시간(TMODOUT) 설정 확인
    # GOOD: TMOUT이 600초(10분) 이하로 설정된 경우
    # VULNERABLE: TMOUT이 설정되지 않았거나 600초를 초과하는 경우

    local is_secure=false
    local config_details=""

    # 현재 세션의 TMOUT 확인
    local current_tmout="${TMOUT:-}"
    config_details="현재 세션 TMOUT: ${current_tmout:-未설定}"

    # /etc/profile에서 TMOUT 확인
    local profile_tmout=$(grep -h "TMOUT" /etc/profile /etc/bash.bashrc 2>/dev/null | grep -v "^#" | grep "export TMOUT" || echo "")
    if [ -n "$profile_tmout" ]; then
        config_details="${config_details}${newline}/etc/profile 설정:${newline}${profile_tmout}"
    else
        config_details="${config_details}${newline}/etc/profile: TMOUT 설정 없음"
    fi

    command_result="${config_details}"
    command_executed="echo \$TMOUT && grep -h TMOUT /etc/profile /etc/bash.bashrc"

    # 최종 판정
    if [ -n "$current_tmout" ]; then
        # TMOUT이 설정된 경우
        if [ "$current_tmout" -le 600 ] 2>/dev/null; then
            is_secure=true
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="세션 종료시간이 적절히 설정됨 (TMOUT=${current_tmout}초, 600초 이하)${newline}${config_details}"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="세션 종료시간이 너무 김 (TMOUT=${current_tmout}초, 600초 이하 권장)${newline}${config_details}"
        fi
    else
        # TMOUT이 설정되지 않은 경우
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="세션 종료시간이 설정되지 않음 (보안 위험)${newline}${config_details}"
    fi

    # 결과 생성
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

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
