#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-19
# ============================================================================
# [점검 항목 상세]
# @ID          : U-07
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 하
# @Title       : 불필요한 계정 제거
# @Description : 불필요한 기본 계정(lp, uucp, nuucp 등) 및 장기 미사용 계정 존재 여부 점검
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

ITEM_ID="U-07"
ITEM_NAME="불필요한 계정 제거"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 계정이 존재하는지 점검하여 관리되지 않은 계정에 의한 침입에 대비하는지 확인하기 위함"
GUIDELINE_THREAT="로그인이 가능하고 현재 사용하지 않는 불필요한 계정은 사용 중인 계정보다 상대적으로 관리가 취약하여 공격자의 목표가 되어 계정이 탈취될 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 계정(lp, uucp, nuucp 등)이 존재하지 않거나, 장기 미사용 계정이 없는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 계정이 존재하거나, 장기 미사용 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="시스템에 존재하는 계정 확인 후 불필요한 계정 제거"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # 1. 불필요한 기본 계정 확인 (lp, uucp, nuucp)
    # 2. 장기 미사용 계정 확인 (참고용)

    local is_vulnerable=false
    local vuln_details=""
    
    # 1. 기본 계정 점검
    local default_accounts_regex="^(lp|uucp|nuucp):"
    local default_accounts_output=$(grep -E "$default_accounts_regex" /etc/passwd 2>/dev/null || echo "")
    
    if [ -n "$default_accounts_output" ]; then
        is_vulnerable=true
        vuln_details="불필요한 기본 계정 발견"
    fi

    local lastlog_output=""
    if command -v lastlog >/dev/null 2>&1; then
        lastlog_output=$(lastlog 2>/dev/null | head -20)
    elif command -v last >/dev/null 2>&1; then
        lastlog_output="[last command output]${newline}$(last -10 2>/dev/null)"
    else
        lastlog_output="lastlog/last command not available"
    fi

    command_result="[Check 1: Default Unnecessary Accounts]${newline}${default_accounts_output:-No default accounts found (lp, uucp, nuucp)}${newline}${newline}[Check 2: Login History]${newline}${lastlog_output}"
    command_executed="grep -E '^(lp|uucp|nuucp):' /etc/passwd"

    if [ "$is_vulnerable" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${vuln_details} 확인됨. (${default_accounts_output})"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 기본 계정이 존재하지 않음"
    fi

    # 결과 저장
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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
