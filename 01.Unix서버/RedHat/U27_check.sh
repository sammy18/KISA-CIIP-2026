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
GUIDELINE_PURPOSE="r-command를 통한 별도의 인증 없는 관리자 권한 원격 접속을 차단하기 위함"
GUIDELINE_THREAT="r-command(rlogin, rsh 등)에 보안 설정이 적용되지 않을 경우, 원격지의 공격자가 관리자 권한으로 목표 시스템상 임의의 명령을 수행시킬 수 있으며, 명령어 원격 실행을 통해 중요 정보 유출 및 시스템 장애를 유발 또는 공격자의 백 도어 등으로도 활용될 수 있는 위험이 존재함 해당 파일은 r-command 서비스의 접근 통제에 관련된 파일이며, 권한 설정이 부적절한 경우 r-command 서비스 사용 권한을 임의로 등록하여 무단 사용 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="rlogin,rsh,rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에'+'설정이 없는 경우"
GUIDELINE_CRITERIA_BAD="rlogin,rsh,rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우"
GUIDELINE_REMEDIATION="/etc/hosts.equiv, $HOME/.rhosts 파일 소유자 및 권한 변경, 허용 호스트 및 계정 등록 설정"

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
