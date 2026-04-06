#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-49
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : DNS 보안 버전 패치
# @Description : DNS 서비스(BIND)의 최신 보안 패치 적용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-49"
ITEM_NAME="DNS 보안 버전 패치"
SEVERITY="(상)"

GUIDELINE_PURPOSE="취약점이발표되지않은BIND버전을사용하여시스템보안성을높이기위함"
GUIDELINE_THREAT="취약점이 내포된 BIND 버전을 사용할 경우, DoS 공격, 버퍼 오버플로우(Buffer Overflow) 및 DNS 서버원격침입등의위험이존재함"
GUIDELINE_CRITERIA_GOOD="주기적으로패치를관리하는경우"
GUIDELINE_CRITERIA_BAD="주기적으로패치를관리하고있지않은경우"
GUIDELINE_REMEDIATION="Ÿ DNS서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ DNS서비스사용시패치관리정책수립및주기적으로패치적용설정 ※ DNS서비스의경우대부분의버전에서취약점이보고되고있으므로OS관리자, 서비스 개발자가 패치적용에따른서비스영향정도를정확히파악하여주기적인패치적용정책수리후적용"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="DNS 서비스가 최신 버전이거나 설치되지 않았습니다."
    local command_result=""
    local command_executed="named -v"

    local bind_ver=$(named -v 2>/dev/null || echo "Not Installed")
    if [ "$bind_ver" != "Not Installed" ]; then
        command_result="현재 BIND 버전: [ ${bind_ver} ]"
        inspection_summary="DNS 서비스(BIND)가 실행 중입니다. 최신 보안 패치 여부를 수동으로 확인하십시오."
    else
        command_result="BIND(DNS) 서비스가 설치되어 있지 않습니다."
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
