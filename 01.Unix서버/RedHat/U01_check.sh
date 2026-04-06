#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-01
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : root 계정 원격 접속 제한
# @Description : 원격 터미널을 이용한 root 계정의 직접 접속 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-01"
ITEM_NAME="root 계정 원격 접속 제한"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="관리자 계정 탈취로 인한 시스템 장악을 방지하기 위해 외부 비인가자의 root 계정 접근 시도를 원천적으로차단하기위함"
GUIDELINE_THREAT="root 계정은 운영체제의 모든 기능을 설정 및 변경이 가능하여(프로세스, 커널 변경 등) root 계정을 탈취하여외부에서원격을이용한시스템장악및각종공격으로(무차별대입공격, 사전대입공격등) 인한root계정사용불가위험이존재함"
GUIDELINE_CRITERIA_GOOD="원격터미널서비스를사용하지않거나,사용시root직접접속을차단한경우"
GUIDELINE_CRITERIA_BAD="원격터미널서비스사용시root직접접속을허용한경우"
GUIDELINE_REMEDIATION="원격접속시root계정으로접속할수없도록파일내용설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="root 계정 원격 접속 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -i '^PermitRootLogin' /etc/ssh/sshd_config"

    # 1. 실제 데이터 추출
    local ssh_val=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' || echo "no-setting")
    local securetty_pts=$(grep -E "^pts/" /etc/securetty || echo "no-pts")

    # 2. 판정 로직
    if [[ "$ssh_val" =~ ^[Yy]es ]] || [ "$ssh_val" = "no-setting" ] || [ "$securetty_pts" != "no-pts" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="root 계정 원격 접속 제한 설정이 미설정 또는 부적절합니다."
    fi

    # 3. command_result에 실제 설정값 기록 (증적 데이터)
    command_result="[SSH] PermitRootLogin=${ssh_val} | [Telnet] /etc/securetty PTS=${securetty_pts}"

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
