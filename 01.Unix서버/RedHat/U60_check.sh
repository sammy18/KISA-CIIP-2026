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

GUIDELINE_PURPOSE="SNMP 서비스의 Community String의 복잡성 설정을 통해 비인가자의 비밀번호 추측 공격에 대비하기 위함"
GUIDELINE_THREAT="Community String에 복잡성 설정이 되어 있지 않을 경우, 비인가자가 비밀번호 추측 공격을 통해 계정 탈취 시 환경 설정 파일 열람 및 수정, 각종 정보 수집, 관리자 권한 획득 등 다양한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자 포함 10 자리 이상 또는 영문자, 숫자, 특수 문자 포함 8 자리 이상인 경우 ※ SNMPv3의 경우 별도 인증 기능을 사용하고, 해당 비밀번호가 복잡 도를 만족하는 경우 양호"
GUIDELINE_CRITERIA_BAD="아래의 내용 중 하나라도 해당되는 경우 1. SNMP Community String 기본값인'public', 'private'일 경우 2. 영문자, 숫자 포함 10 자리 미만인 경우 3. 영문자, 숫자, 특수 문자 포함 8 자리 미만인 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 SNMP 서비스 사용 시 SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자 포함 10 자리 이상 또는 영문자, 숫자, 특수 문자 포함 8 자리 이상으로 설정"

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
