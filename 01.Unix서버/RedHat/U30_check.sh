#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-30
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : UMASK 설정 관리
# @Description : 신규 파일 및 디렉터리 생성 시 기본 권한을 제어하는 UMASK 설정 여부 점검
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

ITEM_ID="U-30"
ITEM_NAME="UMASK 설정 관리"
SEVERITY="(중)"

# 가이드라인 정보
GUIDELINE_PURPOSE="잘못설정된UMASK값으로인해신규파일에대한권한이과도하게부여되는것을방지하기위함"
GUIDELINE_THREAT="잘못설정된UMASK로인해파일및디렉터리생성시과도한권한이부여되어무단액세스및데이터 유출의위험이존재함"
GUIDELINE_CRITERIA_GOOD="UMASK값이022이상으로설정된경우"
GUIDELINE_CRITERIA_BAD="UMASK값이022미만으로설정된경우"
GUIDELINE_REMEDIATION="설정파일에UMASK값을022로설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="UMASK 설정이 022 이상으로 적절하게 설정되어 있습니다."
    local command_result=""
    local command_executed="umask"

    # 1. 실제 데이터 추출
    local current_umask
    current_umask=$(umask)

    # 2. 판정 로직 (022보다 크거나 같은지 확인)
    if [ "$current_umask" -lt 022 ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="UMASK 설정이 022 미만으로 취약하게 설정되어 있습니다."
    fi

    # 3. command_result에 실제 설정값 기록
    command_result="현재 시스템 UMASK: [ ${current_umask} ]"

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
