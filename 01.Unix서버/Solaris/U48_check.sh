#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-48
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : Solaris
# @Severity    : 중
# @Title       : expn, vrfy 명령어 제한
# @Description : SMTP 서버의 EXPN 및 VRFY 명령어 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-48"
ITEM_NAME="expn, vrfy 명령어 제한"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="SMTP 서비스의 expn,vrfy 명령을 통한 정보 유출을 방지하기 위함"
GUIDELINE_THREAT="expn, vrfy 명령어를 통하여 특정 사용자 계정의 존재 여부를 알 수 있고, 사용자의 정보를 외부로 유출할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="noexpn, novrfy 옵션이 설정된 경우"
GUIDELINE_CRITERIA_BAD="noexpn, novrfy 옵션이 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn,novrfy 또는 goaway 옵션 추가 설정"

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # ==========================================================================
    # 1. SMTP 서비스 실행 여부 확인 (Solaris SMF)
    # ==========================================================================
    local smtp_running=false
    local smtp_service=""

    if svcs sendmail 2>/dev/null | grep -q "online"; then
        smtp_running=true
        smtp_service="sendmail"
    elif svcs postfix 2>/dev/null | grep -q "online"; then
        smtp_running=true
        smtp_service="postfix"
    fi

    command_executed="svcs sendmail postfix 2>/dev/null; grep 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null"

    # ==========================================================================
    # 2. SMTP 미사용 시 양호
    # ==========================================================================
    if [ "$smtp_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SMTP 서비스가 실행 중이지 않습니다."
        command_result="SMTP Service: [inactive]"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 3. SMTP 실행 중인 경우 expn/vrfy 설정 확인
    # ==========================================================================
    local expn_secure=false
    local vrfy_secure=false
    local details=""

    if [ "$smtp_service" = "sendmail" ]; then
        local cf_file="/etc/mail/sendmail.cf"
        if [ -f "$cf_file" ]; then
            local privacy_opts=$(grep "O PrivacyOptions" "$cf_file" 2>/dev/null | sed 's/.*=//' || echo "")
            if echo "$privacy_opts" | grep -qi "goaway"; then
                expn_secure=true
                vrfy_secure=true
                details="PrivacyOptions에 goaway 설정됨"
            else
                echo "$privacy_opts" | grep -qi "noexpn" && expn_secure=true
                echo "$privacy_opts" | grep -qi "novrfy" && vrfy_secure=true
                details="PrivacyOptions: ${privacy_opts:-미설정}"
            fi
        fi
    elif [ "$smtp_service" = "postfix" ]; then
        expn_secure=true
        vrfy_secure=true
        details="Postfix (기본 expn/vrfy 차단)"
    fi

    # ==========================================================================
    # 4. 판정
    # ==========================================================================
    if [ "$expn_secure" = true ] && [ "$vrfy_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SMTP 서비스의 expn, vrfy 명령어가 제한되어 있습니다. (${details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        local missing=""
        [ "$expn_secure" = false ] && missing="noexpn "
        [ "$vrfy_secure" = false ] && missing="${missing}novrfy "
        inspection_summary="SMTP 서비스(${smtp_service})에서 ${missing}옵션이 설정되지 않았습니다."
    fi

    command_result="${details}"
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
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
