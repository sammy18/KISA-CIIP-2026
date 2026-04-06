#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-66
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : SNMP 서비스 실행 권한 제한
# @Description : SNMP 서비스가 root 권한으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-66"
ITEM_NAME="SNMP 서비스 실행 권한 제한"
SEVERITY="(중)"

GUIDELINE_PURPOSE="보안사고발생시원인파악및각종침해사실확인을하기위함"
GUIDELINE_THREAT="로깅 설정이 되어 있지 않을 경우, 원인 규명이 어려우며 법적 대응을 위한 충분한 증거로 사용할 수 없는위험이존재함"
GUIDELINE_CRITERIA_GOOD="로그기록정책이보안정책에따라설정되어수립되어있으며,로그를남기고있는경우"
GUIDELINE_CRITERIA_BAD="로그기록정책미수립또는정책에따라설정되어있지않거나,로그를남기고있지않은경우"
GUIDELINE_REMEDIATION="로그기록정책을수립하고,정책에따라(r)syslog.conf파일을설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="SNMP 서비스 실행 권한이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep snmpd"

    local snmp_ps=$(ps -ef | grep "snmpd" | grep -v grep || echo "")
    if [ -n "$snmp_ps" ]; then
        local snmp_user=$(echo "$snmp_ps" | awk '{print $1}')
        if [ "$snmp_user" = "root" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="SNMP 서비스가 root 권한으로 실행 중입니다."
        fi
        command_result="SNMP 실행 계정: [ ${snmp_user} ]"
    else
        command_result="SNMP 서비스가 실행 중이지 않습니다."
    fi
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
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}
main "$@"
