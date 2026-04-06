#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-45
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 메일 서비스 버전 점검
# @Description : 사용 중인 Sendmail 등 메일 서비스 프로그램의 최신 버전 사용 여부 점검
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"; source "${LIB_DIR}/output_mode.sh"; source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-45"; ITEM_NAME="메일 서비스 버전 점검"; SEVERITY="(상)"

GUIDELINE_PURPOSE="메일 서비스 사용 목적 검토 및 취약점이 없는 버전의 사용 유무 점검으로 최적화된 메일 서비스의 운영하기위함"
GUIDELINE_THREAT="취약점이 발견된 메일 버전의 경우 버퍼 오버플로우(Buffer Overflow) 공격에 의한 시스템 권한 획득 및주요정보노출의위험이존재함"
GUIDELINE_CRITERIA_GOOD="메일서비스버전이최신버전인경우"
GUIDELINE_CRITERIA_BAD="메일서비스버전이최신버전이아닌경우"
GUIDELINE_REMEDIATION="Ÿ 메일서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ 메일서비스사용시패치관리정책을수립하여주기적으로패치적용설정"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local inspection_summary="메일 서비스가 비활성화되어 있거나 최신 상태를 유지하고 있습니다."
    local command_result=""
    
    local mail_proc=$(ps -ef | grep -Ei "sendmail|postfix" | grep -v grep || echo "")

    if [ -n "$mail_proc" ]; then
        # 버전 확인 명령어 실행 (예: sendmail -d0.1)
        local mail_ver=$(/usr/sbin/sendmail -d0.1 < /dev/null 2>&1 | grep "Version" | head -n 1 || echo "Unknown")
        command_result="실행 중인 메일 서비스 버전: [ ${mail_ver} ]"
        inspection_summary="메일 서비스가 실행 중입니다. 수동으로 최신 버전 여부를 확인하십시오."
    else
        command_result="메일 서비스 프로세스가 발견되지 않았습니다."
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "sendmail -d0.1" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
