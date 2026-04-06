#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-27
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : 원격 접속 시 인증 없이 접근 가능한 설정 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"

ITEM_ID="U-27"; ITEM_NAME="\$HOME/.rhosts, hosts.equiv 사용 금지"; SEVERITY="(상)"
GUIDELINE_PURPOSE="r-command를통한별도의인증없는관리자권한원격접속을차단하기위함"
GUIDELINE_THREAT="Ÿ r-command(rlogin, rsh 등)에 보안 설정이 적용되지 않을 경우, 원격지의 공격자가 관리자 권한으로 목표 시스템상 임의의 명령을 수행시킬 수 있으며, 명령어 원격실행을 통해 중요 정보유출 및시스템장애를유발또는공격자의백도어등으로도활용될수있는위험이존재함 Ÿ 해당 파일은 r-command 서비스의 접근통제에 관련된 파일이며, 권한 설정이 부적절한 경우 r-command서비스사용권한을임의로등록하여무단사용위험이존재함"
GUIDELINE_CRITERIA_GOOD="rlogin,rsh,rexec서비스를사용하지않거나,사용시아래와같은설정이적용된경우 1. /etc/hosts.equiv 및$HOME/.rhosts파일소유자가root또는해당계정인경우 2. /etc/hosts.equiv 및$HOME/.rhosts파일권한이600이하인경우 3. /etc/hosts.equiv 및$HOME/.rhosts파일설정에'+'설정이없는경우 취약: rlogin,rsh,rexec서비스를사용하며아래와같은설정이적용되지않은경우 1. /etc/hosts.equiv및$HOME/.rhosts파일소유자가root또는해당계정이아닌경우"
GUIDELINE_CRITERIA_BAD="해당 서비스를 사용하며 소유자/권한이 부적절하거나 '+' 설정이 존재하는 경우"
GUIDELINE_REMEDIATION="/etc/hosts.equiv,$HOME/.rhosts파일소유자및권한변경,허용호스트및계정등록설정"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local command_result=""; local command_executed="ls -l /etc/hosts.equiv $HOME/.rhosts"

    local equiv="/etc/hosts.equiv"
    local rhosts="$HOME/.rhosts"
    local evidence=""

    if [ -f "$equiv" ]; then
        local owner=$(stat -c "%U" "$equiv")
        local perm=$(stat -c "%a" "$equiv")
        local content=$(grep "+" "$equiv")
        evidence+="/etc/hosts.equiv(Owner:${owner}, Perm:${perm}) "
        if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] || [ -n "$content" ]; then status="취약"; diagnosis_result="VULNERABLE"; fi
    fi

    command_result="설정 현황: ${evidence:-파일 없음}"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "점검 완료" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
