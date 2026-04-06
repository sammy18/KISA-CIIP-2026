#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-37
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : crontab 설정파일 권한 설정 미흡
# @Description : 정기적인 작업을 수행하는 crontab 관련 파일의 권한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-37"
ITEM_NAME="crontab 설정파일 권한 설정 미흡"
SEVERITY="(상)"

GUIDELINE_PURPOSE="관리자외에는서비스를사용할수없도록설정하고있는지점검하기위함"
GUIDELINE_THREAT="일반 사용자가 crontab 및 at 서비스를 사용할 수 있을 경우, 고의 또는 실수로 불법적인 예약 파일 실행으로시스템피해를일으킬수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="crontab및at명령어에일반사용자실행권한이제거되어있으며,cron및at관련파일권한이 640이하인경우"
GUIDELINE_CRITERIA_BAD="crontab및at명령어에일반사용자실행권한이부여되어있으며,cron및at관련파일권한이 640이상인경우"
GUIDELINE_REMEDIATION="crontab및at명령어파일권한750이하,cron및at관련파일소유자및파일권한640이하설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="crontab 관련 파일의 권한 및 소유자 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/crontab"

    # 1. 실제 데이터 추출
    local cron_file="/etc/crontab"
    if [ -f "$cron_file" ]; then
        local owner=$(stat -c "%U" "$cron_file")
        local perm=$(stat -c "%a" "$cron_file")
        local ls_out=$(ls -l "$cron_file")

        # 2. 판정 로직
        if [ "$owner" != "root" ] || [ "$perm" -gt 640 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="crontab 설정 파일의 권한 또는 소유자 설정이 미흡합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        command_result="crontab 파일을 찾을 수 없습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
