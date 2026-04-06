#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-60
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : SNMP 서비스 Community String 복잡성 설정
# @Description : 기본 Community String(public, private) 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-60"
ITEM_NAME="SNMP 서비스 Community String 복잡성 설정"
SEVERITY="(중)"

GUIDELINE_PURPOSE="SNMP 서비스의 Community String의 복잡성 설정을 통해 비인가자의 비밀번호 추측 공격에 대비하기위함"
GUIDELINE_THREAT="Community String에 복잡성 설정이 되어 있지 않을 경우, 비인가자가 비밀번호 추측 공격을 통해 계정탈취시환경설정파일열람및수정,각종정보수집,관리자권한획득등다양한위험이존재함"
GUIDELINE_CRITERIA_GOOD="SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자 포함 10자리 이상또는영문자,숫자,특수문자포함8자리이상인경우 ※ SNMPv3의경우별도인증기능을사용하고,해당비밀번호가복잡도를만족하는경우양호"
GUIDELINE_CRITERIA_BAD="아래의내용중하나라도해당되는경우 1. SNMP Community String 기본값인'public', 'private'일경우 2.영문자,숫자포함10자리미만인경우 3.영문자,숫자,특수문자포함8자리미만인경우"
GUIDELINE_REMEDIATION="Ÿ SNMP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ SNMP 서비스 사용 시 SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자포함10자리이상또는영문자,숫자,특수문자포함8자리이상으로설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="기본 Community String이 발견되지 않았습니다."
    local command_result=""
    local command_executed="grep -Ei 'public|private' /etc/snmp/snmpd.conf"

    if [ -f "/etc/snmp/snmpd.conf" ]; then
        local default_strings=$(grep -Ei "public|private" /etc/snmp/snmpd.conf | grep -v "^#" | xargs || echo "")
        if [ -n "$default_strings" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="추측하기 쉬운 기본 Community String(public/private)이 사용 중입니다."
            command_result="발견된 설정: [ ${default_strings} ]"
        fi
    fi
    command_result=$(echo "${command_result:-설정 안전함}" | tr -d '\n\r')

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
