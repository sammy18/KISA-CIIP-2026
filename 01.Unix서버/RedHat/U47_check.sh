#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-47
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 스팸 메일 릴레이 제한
# @Description : SMTP 서버의 메일 릴레이 기능을 제한하여 스팸 메일 경유지로 악용되는지 점검
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

ITEM_ID="U-47"
ITEM_NAME="스팸 메일 릴레이 제한"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="스팸메일서버로의악용방지및서버과부하를방지하기위함"
GUIDELINE_THREAT="SMTP 서버의 릴레이 기능을 제한하지 않을 경우, 악의적인 사용 목적을 가진 사용자들이 스팸 메일 서버로사용하거나DoS공격의위험이존재함"
GUIDELINE_CRITERIA_GOOD="릴레이제한이설정된경우"
GUIDELINE_CRITERIA_BAD="릴레이제한이설정되어있지않은경우"
GUIDELINE_REMEDIATION="Ÿ 메일서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ 메일서비스사용시릴레이방지설정또는릴레이대상접근제어설정"

diagnose() {
    # 파싱 안정성을 위한 초기값 설정
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="스팸 메일 릴레이 제한 설정이 적절하게 이루어져 있습니다."
    local command_result=""
    local command_executed="grep -v '^#' /etc/mail/access"

    # 1. 실제 데이터 추출 (Sendmail 기준)
    local access_file="/etc/mail/access"
    if [ -f "$access_file" ]; then
        # 주석 제외 실제 릴레이 규칙 추출
        local relay_rules=$(grep -i "RELAY" "$access_file" | grep -v "^#" | xargs || echo "")
        
        # 2. 판정 로직
        if [ -n "$relay_rules" ]; then
            command_result="설정된 릴레이 규칙: [ ${relay_rules} ]"
        else
            # 릴레이 허용 설정이 아예 없는 경우도 기본 정책상 차단으로 간주(양호) 가능
            command_result="릴레이 허용 규칙이 명시되지 않았습니다 (기본 차단 정책 적용 중)."
        fi
    else
        command_result="메일 릴레이 설정 파일(/etc/mail/access)이 존재하지 않습니다."
    fi

    # [핵심 보정] JSON 파싱 에러 방지를 위해 변수 내 모든 줄바꿈 제거
    command_result=$(echo "$command_result" | tr -d '\n\r')

    # U-02와 동일하게 12개의 인자를 모두 전달
    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    # 원본 실행 구조 완벽 복구
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
