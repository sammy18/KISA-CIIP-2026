#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-18
# ============================================================================
# [점검 항목 상세]
# @ID          : U-03
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : 계정 잠금 임계값 설정
# @Description : pam_faillock.so 또는 pam_tally2.so 설정 확인
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

ITEM_ID="U-03"
ITEM_NAME="계정 잠금 임계값 설정"
SEVERITY="상"

# 가이드라인 정보 (Spaces added for readability)
GUIDELINE_PURPOSE="계정 탈취 목적의 무차별 대입 공격 시 해당 계정을 잠금으로써 인증 요청에 응답하는 리소스 낭비를 차단하고 대입공격으로 인한 비밀번호 노출 공격을 무력화하기 위함"
GUIDELINE_THREAT="계정 잠금 임계값이 설정되어 있지 않을 경우, 비밀번호 탈취 공격(무차별 대입 공격, 사전 대입 공격, 추측 공격 등)의 인증 요청에 대해 설정된 비밀번호가 일치할 때까지 지속적으로 응답하여 해당 계정의 비밀번호가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
GUIDELINE_CRITERIA_BAD="계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="계정 잠금 임계값을 10회 이하로 설정"

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
    # pam_faillock.so 또는 pam_tally2.so 설정 확인
    
    local is_secure=false
    local config_details="설정 없음"
    local matched_pam_file=""
    local pam_module_name=""
    local raw_pam_output=""
    local deny_val=""

    # 1) PAM Configuration Files to check
    # Priority: system-auth > password-auth > common-auth > login
    local pam_auth_files=(
        "/etc/pam.d/system-auth"
        "/etc/pam.d/password-auth"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/login"
    )

    for pam_file in "${pam_auth_files[@]}"; do
        if [ -f "$pam_file" ]; then
            # Search for faillock or tally2
            # Needs to check 'auth' or 'account' lines, focusing on 'deny=' parameter
            if grep -E "pam_faillock.so|pam_tally2.so" "$pam_file" | grep -v "^#" > /dev/null; then
                matched_pam_file="$pam_file"
                raw_pam_output=$(grep -E "pam_faillock.so|pam_tally2.so" "$pam_file" | grep -v "^#" || true)
                
                # Determine which module
                if echo "$raw_pam_output" | grep -q "pam_faillock.so"; then
                    pam_module_name="pam_faillock.so"
                elif echo "$raw_pam_output" | grep -q "pam_tally2.so"; then
                    pam_module_name="pam_tally2.so"
                fi
                
                # Extract 'deny=' value (first occurrence found)
                # Using standard grep/sed/awk for portability
                deny_val=$(echo "$raw_pam_output" | grep -o "deny=[0-9]*" | head -1 | cut -d= -f2 || echo "")
                
                # If deny is found, check value
                if [ -n "$deny_val" ]; then
                   if [ "$deny_val" -le 10 ]; then
                       is_secure=true
                       config_details="${pam_module_name} deny=${deny_val}"
                   else
                       config_details="${pam_module_name} deny=${deny_val} (기준 10회 초과)"
                   fi
                else
                   config_details="${pam_module_name} deny 설정 없음"
                fi
                
                break # Stop at first relevant file found
            fi
        fi
    done

    # 2) Additional check for faillock.conf if faillock is used but no params in PAM
    local conf_output=""
    if [ "$pam_module_name" == "pam_faillock.so" ] && [ -f "/etc/security/faillock.conf" ]; then
        if [ -z "$deny_val" ]; then
             # Check conf file
             conf_output=$(grep -E "^deny" "/etc/security/faillock.conf" | grep -v "^#" || true)
             local conf_deny=$(echo "$conf_output" | cut -d= -f2 | tr -d ' ')
             if [ -n "$conf_deny" ]; then
                 if [ "$conf_deny" -le 10 ]; then
                     is_secure=true
                     config_details="${config_details:-pam_faillock.so} (conf: deny=${conf_deny})"
                 else
                     config_details="${config_details:-pam_faillock.so} (conf: deny=${conf_deny} 기준 초과)"
                 fi
             fi
        fi
    fi

    # --- Execute commands and capture Raw Output ---
    # First, attempt to find PAM configuration with actual command output
    local raw_all_pam_files_output=""
    local all_checked_files=""

    # Build command_executed for all files we'll check
    local cmds_to_run=()
    for pam_file in "${pam_auth_files[@]}"; do
        if [ -f "$pam_file" ]; then
            cmds_to_run+=("grep -E 'pam_faillock.so|pam_tally2.so' '${pam_file}' 2>/dev/null || true")
            all_checked_files="${all_checked_files} ${pam_file}"
        fi
    done

    # Execute the grep command that matches what we actually use in diagnosis
    # Capture actual grep output for raw command_result
    if [ -n "$matched_pam_file" ]; then
        # Re-execute to get clean raw output
        raw_pam_output=$(grep -E "pam_faillock.so|pam_tally2.so" "$matched_pam_file" 2>/dev/null | grep -v "^#" || echo "")
        command_result="[FILE: ${matched_pam_file}]${newline}${raw_pam_output}${newline}"
        command_executed="grep -E 'pam_faillock.so|pam_tally2.so' '${matched_pam_file}'"
    else
        # No PAM file found - capture actual grep output from all files
        local temp_output=""
        for pam_file in "${pam_auth_files[@]}"; do
            if [ -f "$pam_file" ]; then
                local grep_result=$(grep -E "pam_faillock.so|pam_tally2.so" "$pam_file" 2>/dev/null || echo "")
                if [ -n "$grep_result" ]; then
                    temp_output="${temp_output}[${pam_file}]${newline}${grep_result}${newline}"
                fi
            fi
        done
        command_result="${temp_output:-[No pam_faillock.so or pam_tally2.so found in PAM configuration files]}${newline}"
        command_executed="grep -E 'pam_faillock.so|pam_tally2.so' /etc/pam.d/{system-auth,password-auth,common-auth,login}"
    fi

    # Capture faillock.conf raw output if applicable
    if [ -f "/etc/security/faillock.conf" ]; then
        conf_output=$(grep -E "^deny" "/etc/security/faillock.conf" 2>/dev/null | grep -v "^#" || echo "")
        if [ -n "$conf_output" ]; then
            command_result="${command_result}[FILE: /etc/security/faillock.conf]${newline}${conf_output}${newline}"
            command_executed="${command_executed}; grep -E '^deny' /etc/security/faillock.conf"
        fi
    fi

    # --- Final Judgment ---
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="계정 잠금 임계값이 적절하게 설정됨 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정 잠금 임계값이 설정되지 않았거나 기준(10회)을 초과함 (${config_details})"
    fi

    # Cross-platform note
    # ※ AIX: /etc/security/user (loginretries), HP-UX: /etc/default/security (AUTH_MAXTRIES), Solaris: /etc/default/login (RETRIES)

    # 결과 저장 (통합형 인자 사용)
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
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
