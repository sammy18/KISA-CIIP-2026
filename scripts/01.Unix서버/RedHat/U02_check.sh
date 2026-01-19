#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-18
# ============================================================================
# [점검 항목 상세]
# @ID          : U-02
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : 비밀번호 관리 정책 설정
# @Description : 비밀번호 복잡성 설정 및 최소/최대 사용 기간 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

# set -euo pipefail  # Temporarily disabled for debugging

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

ITEM_ID="U-02"
ITEM_NAME="비밀번호 관리 정책 설정"
SEVERITY="HIGH"

# 가이드라인 정보 (Spaces added for readability based on standard Korean spacing)
GUIDELINE_PURPOSE="사용자의 비밀번호 복잡성과 주기적 변경을 통해 시스템 보안을 강화하기 위함"
GUIDELINE_THREAT="비밀번호 관련 정책이 설정되지 않을 경우, 비인가자의 각종 공격(무차별 대입 공격, 사전 대입 공격 등)에 의해 비밀번호가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="비밀번호 관리 정책이 설정된 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 관리 정책이 설정되지 않은 경우"
GUIDELINE_REMEDIATION="root 계정을 포함한 사용자 계정의 비밀번호를 영문, 숫자, 특수문자를 포함하여 최소 8자리 이상 및 최소사용기간 1일, 최대사용기간 90일, 최근비밀번호 기억 4회 이상으로 설정"

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
    # 1. Password Complexity (PAM)
    # 2. Password Age (/etc/login.defs)

    local complexity_ok=false
    local age_ok=false
    local config_details=""
    
    # --- 1. Password Complexity Check ---
    local pam_files=(
        "/etc/pam.d/system-auth"
        "/etc/pam.d/password-auth"
        "/etc/pam.d/common-password"
    )
    
    local pam_output=""
    local pam_file_used=""
    local found_pam=false
    local minlen=""
    local ucredit=""
    local lcredit=""
    local dcredit=""
    local ocredit=""

    for pfile in "${pam_files[@]}"; do
        if [ -f "$pfile" ]; then
            if grep -E "pam_pwquality\.so|pam_cracklib\.so" "$pfile" | grep -v "^#" > /dev/null; then
                pam_file_used="$pfile"
                pam_output=$(grep -E "pam_pwquality\.so|pam_cracklib\.so" "$pfile" | grep -v "^#" || true)
                found_pam=true
                break
            fi
        fi
    done

    # If using pwquality, also check /etc/security/pwquality.conf
    local pwquality_conf_output=""
    if [ -f "/etc/security/pwquality.conf" ]; then
        pwquality_conf_output=$(grep -E "^(minlen|dcredit|ucredit|lcredit|ocredit)" "/etc/security/pwquality.conf" | grep -v "^#" || true)
    fi

    if [ "$found_pam" = true ]; then
        # Check values (parsing from pam line OR pwquality.conf)
        # Simplified parsing logic for demonstration (checking if values exist and are compliant)
        # Note: Actual robust parsing might separate file and line checks.
        
        # Merge outputs for parsing
        local combined_config="${pam_output} ${pwquality_conf_output}"
        
        minlen=$(echo "$combined_config" | grep -oP 'minlen=\K[0-9]+' | head -1 || echo "$combined_config" | grep -oP 'minlen\s*=\s*\K[0-9]+' | head -1 || echo "")
        ucredit=$(echo "$combined_config" | grep -oP 'ucredit=\K-?[0-9]+' | head -1 || echo "$combined_config" | grep -oP 'ucredit\s*=\s*\K-?[0-9]+' | head -1 || echo "")
        lcredit=$(echo "$combined_config" | grep -oP 'lcredit=\K-?[0-9]+' | head -1 || echo "$combined_config" | grep -oP 'lcredit\s*=\s*\K-?[0-9]+' | head -1 || echo "")
        dcredit=$(echo "$combined_config" | grep -oP 'dcredit=\K-?[0-9]+' | head -1 || echo "$combined_config" | grep -oP 'dcredit\s*=\s*\K-?[0-9]+' | head -1 || echo "")
        ocredit=$(echo "$combined_config" | grep -oP 'ocredit=\K-?[0-9]+' | head -1 || echo "$combined_config" | grep -oP 'ocredit\s*=\s*\K-?[0-9]+' | head -1 || echo "")

        # Default check (Assume compliant if set, strictly check numbers)
        local c_check=0
        [ -n "$minlen" ] && [ "$minlen" -ge 8 ] && ((c_check++))
        [ -n "$ucredit" ] && [ "$ucredit" -le -1 ] && ((c_check++))
        [ -n "$lcredit" ] && [ "$lcredit" -le -1 ] && ((c_check++))
        [ -n "$dcredit" ] && [ "$dcredit" -le -1 ] && ((c_check++))
        [ -n "$ocredit" ] && [ "$ocredit" -le -1 ] && ((c_check++))

        if [ "$c_check" -ge 5 ]; then
            complexity_ok=true
        fi
        config_details="[복잡성] minlen=${minlen:-X}, u/l/d/o_credit=${ucredit:-X}/${lcredit:-X}/${dcredit:-X}/${ocredit:-X}"
    else
        config_details="[복잡성] 미설정"
    fi

    # --- 2. Password Age Check ---
    local login_output=""
    local max_days=""
    local min_days=""
    
    if [ -f "/etc/login.defs" ]; then
        login_output=$(grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS" "/etc/login.defs" | grep -v "^#" || true)
        max_days=$(echo "$login_output" | grep "PASS_MAX_DAYS" | awk '{print $2}')
        min_days=$(echo "$login_output" | grep "PASS_MIN_DAYS" | awk '{print $2}')
        
        if [ -n "$max_days" ] && [ -n "$min_days" ] && [ "$max_days" -le 90 ] && [ "$min_days" -ge 1 ]; then
            age_ok=true
        fi
        config_details="${config_details} | [기간] MAX=${max_days:-X}, MIN=${min_days:-X}"
    else
        config_details="${config_details} | [기간] /etc/login.defs 없음"
    fi

    # --- Construct command_result (Raw Output) ---
    if [ -n "$pam_file_used" ]; then
        command_result="[${pam_file_used}]"$'\n'"${pam_output}"$'\n'"$'\n'"
        command_executed="grep -E 'pam_pwquality.so|pam_cracklib.so' ${pam_file_used}"
    fi

    if [ -n "$pwquality_conf_output" ]; then
        command_result="${command_result}[/etc/security/pwquality.conf]"$'\n'"${pwquality_conf_output}"$'\n'"$'\n'"
        command_executed="${command_executed}; cat /etc/security/pwquality.conf"
    fi

    if [ -n "$login_output" ]; then
        command_result="${command_result}[/etc/login.defs]"$'\n'"${login_output}"
        command_executed="${command_executed}; grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS' /etc/login.defs"
    else
        command_result="${command_result}[/etc/login.defs]"$'\n'"[FILE NOT FOUND or configuration not found]"
    fi

    # --- Final Judgment ---
    if [ "$complexity_ok" = true ] && [ "$age_ok" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 관리 정책(복잡성 및 사용 기간)이 적절하게 설정됨 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 관리 정책이 미흡함 (${config_details})"
    fi

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
