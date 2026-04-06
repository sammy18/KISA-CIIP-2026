#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-26
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev 디렉터리에 device 파일이 아닌 일반 파일이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"

ITEM_ID="U-26"; ITEM_NAME="/dev에 존재하지 않는 device 파일 점검"; SEVERITY="(상)"
GUIDELINE_PURPOSE="허용한호스트만서비스를사용하게하여서비스취약점을이용한외부자공격을방지하기위함"
GUIDELINE_THREAT="공격자는 rootkit 설정 파일들을 서버 관리자가 쉽게 발견하지 못하도록 /dev 디렉터리에 device 파일인것처럼위장하는수법을사용하는위험이존재함"
GUIDELINE_CRITERIA_GOOD="/dev디렉터리에대한파일점검후존재하지않는device파일을제거한경우"
GUIDELINE_CRITERIA_BAD="/dev디렉터리에대한파일미점검또는존재하지않는device파일을방치한경우"
GUIDELINE_REMEDIATION="major, minor number를가지지않는device파일제거하도록설정"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local command_result=""; local command_executed="find /dev -type f"

    # /dev 디렉토리 내 device 파일이 아닌 일반 파일 탐색
    local fake_dev=$(find /dev -type f 2>/dev/null | xargs)

    if [ -n "$fake_dev" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        command_result="발견된 일반 파일: [ $fake_dev ]"
    else
        command_result="/dev 내 특이 파일 없음"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "점검 완료" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
