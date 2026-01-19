#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-48
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 중
# @Title       : expn, vrfy 명령어 제한
# @Description : SMTP expn/vrfy 명령어 사용 제한 확인
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


ITEM_ID="U-48"
ITEM_NAME="expn, vrfy 명령어 제한"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="SMTP서비스의expn,vrfy명령을통한정보유출을방지하기위함"
GUIDELINE_THREAT="expn, vrfy 명령어를 통하여 특정 사용자 계정의 존재 여부를 알 수 있고, 사용자의 정보를 외부로 유출할수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="noexpn, novrfy옵션이설정된경우"
GUIDELINE_CRITERIA_BAD="noexpn, novrfy옵션이설정되어있지않은경우"
GUIDELINE_REMEDIATION="Ÿ 메일서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ 메일서비스사용시메일서비스설정파일에noexpn,novrfy또는goaway옵션추가설정"

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

    # SMTP expn/vrfy 명령어 제한 확인
    # 양호: noexpn, novrfy 옵션이 설정된 경우
    # 취약: noexpn, novrfy 옵션이 설정되지 않은 경우

    local mail_installed=false
    local has_noexpn=false
    local has_novrfy=false
    local smtp_config=""

    # 1) Sendmail: PrivacyOptions 확인
    local sendmail_cf=""
    if [ -f /etc/mail/sendmail.cf ]; then
        sendmail_cf="/etc/mail/sendmail.cf"
    elif [ -f /etc/sendmail.cf ]; then
        sendmail_cf="/etc/sendmail.cf"
    fi

    if [ -n "$sendmail_cf" ]; then
        mail_installed=true
        local privacy_options=$(grep -i "^O PrivacyOptions" "$sendmail_cf" 2>/dev/null || echo "")
        if [ -n "$privacy_options" ]; then
            smtp_config="${smtp_config}Sendmail PrivacyOptions:${newline}${privacy_options}${newline}"

            # noexpn 확인
            if echo "$privacy_options" | grep -qi "noexpn"; then
                has_noexpn=true
                smtp_config="${smtp_config}  - noexpn: 설정됨${newline}"
            fi

            # novrfy 확인
            if echo "$privacy_options" | grep -qi "novrfy"; then
                has_novrfy=true
                smtp_config="${smtp_config}  - novrfy: 설정됨${newline}"
            fi

            # goaway 옵션 확인 (noexpn, novrfy 포함)
            if echo "$privacy_options" | grep -qi "goaway"; then
                has_noexpn=true
                has_novrfy=true
                smtp_config="${smtp_config}  - goaway: 설정됨 (noexpn, novrfy 포함)${newline}"
            fi
        else
            smtp_config="${smtp_config}Sendmail: PrivacyOptions 설정 없음${newline}"
        fi
    fi

    # 2) Postfix: disable_vrfy_command 확인
    if command -v postconf &>/dev/null; then
        mail_installed=true
        local disable_vrfy=$(postconf disable_vrfy_command 2>/dev/null | grep "disable_vrfy_command" | awk '{print $3}' || echo "")

        smtp_config="${smtp_config}Postfix disable_vrfy_command: ${disable_vrfy}${newline}"

        if [ "$disable_vrfy" = "yes" ]; then
            has_novrfy=true
            smtp_config="${smtp_config}  - vrfy 명령어 비활성화됨${newline}"
        fi
    fi

    # 3) SMTP 서비스 실행 확인
    if systemctl is-active sendmail &>/dev/null || systemctl is-active postfix &>/dev/null || systemctl is-active exim4 &>/dev/null; then
        mail_installed=true
    fi

    # 최종 판정
    if [ "$mail_installed" = false ]; then
        # 메일 서비스가 설치되지 않음 (양호)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SMTP 서비스 미설치됨"
        local raw_smtp_check=$(systemctl is-active sendmail postfix 2>&1; ls /etc/mail/sendmail.cf 2>&1)
        command_result="[Command: systemctl is-active sendmail postfix; ls /etc/mail/sendmail.cf 2>/dev/null]${newline}${raw_smtp_check}"
        command_executed="systemctl is-active sendmail postfix; ls /etc/mail/sendmail.cf 2>/dev/null"
    elif [ "$has_noexpn" = true ] && [ "$has_novrfy" = true ]; then
        # noexpn, novrfy 모두 설정됨 (양호)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="expn, vrfy 명령어 제한됨 (noexpn, novrfy 설정됨)"
        command_result="${smtp_config}"
        command_executed="grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null; postconf disable_vrfy_command"
    else
        # 제한 미설정 (취약)
        local missing_options=()
        [ "$has_noexpn" = false ] && missing_options+=("noexpn")
        [ "$has_novrfy" = false ] && missing_options+=("novrfy")

        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="expn/vrfy 명령어 제한 미흡: ${missing_options[*]} 미설정"
        command_result="${smtp_config}"
        command_executed="grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null; postconf disable_vrfy_command"
    fi

    #echo ""
    #echo "진단 결과: ${status}"
    #echo "판정: ${diagnosis_result}"
    #echo "설명: ${inspection_summary}"
    #echo ""

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
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
