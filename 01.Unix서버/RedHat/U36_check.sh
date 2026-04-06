#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-36
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : r 계열 서비스 비활성화
# @Description : rlogin, rsh, rexec 등 보안에 취약한 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-36"
ITEM_NAME="r 계열 서비스 비활성화"
SEVERITY="(상)"

GUIDELINE_PURPOSE="r-command 사용을 통한 원격 접속은 NET Backup 또는 클러스터링 등 용도로 사용되기도 하나, 인증없이관리자원격접속이가능하여이에대한보안위협을방지하기위함"
GUIDELINE_THREAT="rlogin, rsh, rexec 등의r-command를이용하여원격에서인증절차없이터미널접속, 쉘명령어를 실행이가능한위험이존재함"
GUIDELINE_CRITERIA_GOOD="불필요한r계열서비스가비활성화된경우"
GUIDELINE_CRITERIA_BAD="불필요한r계열서비스가활성화된경우"
GUIDELINE_REMEDIATION="불필요한r계열서비스중지및비활성화설정 ※ NET Backup 등특별한용도로사용하지않는다면shell(514), login(513), exec(512)서비스중 지 ※ rlogin, rsh, rexec 서비스는backup,클러스터링등의용도로종종사용되고있으므로해당서비 스사용유무를확인하여미사용시서비스중지 ※ /etc/hosts.equiv 또는 $HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재 하지않거나해당파일내에설정이없다면사용하지않는것으로간주)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="r 계열 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -E 'rlogin|rsh|rexec'"

    # 1. 실제 데이터 추출
    local r_services=$(ps -ef | grep -Ei "rlogin|rsh|rexec" | grep -v grep || echo "")

    # 2. 판정 로직
    if [ -n "$r_services" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 r 계열 서비스가 활성화되어 있습니다."
        command_result="실행 중인 서비스: [ $(echo $r_services | awk '{print $8}' | xargs) ]"
    else
        command_result="r 계열 서비스가 발견되지 않았습니다."
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
