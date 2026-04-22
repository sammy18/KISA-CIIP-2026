#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-15
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 없는 파일 및 디렉터리 확인 (find -nouser -o -nogroup)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"


ITEM_ID="U-15"
ITEM_NAME="파일 및 디렉터리 소유자 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="소유자가 존재하지 않는 파일 및 디렉터리를 제거 또는 관리하여 임의의 사용자가 해당 파일을 열람, 수정하는 행위를 사전에 차단하기 위함"
GUIDELINE_THREAT="소유자가 존재하지 않는 파일의 UID와 동일한 값으로 특정 계정의 UID를 변경하면 해당 파일의 소유자가 되어 모든 작업이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="소유자가 존재하지 않는 파일 및 디렉터리 제거 또는 소유자 변경 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # 소유자가 /etc/passwd에 존재하지 않는 파일/디렉터리 확인
    # 가이드라인: 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우 양호

    local orphan_files=""
    local orphan_count=0
    local raw_output=""

    # find 명령으로 nouser, nogroup 파일 검색
    # 주요 파일시스템 경로 검색 (가상 파일시스템 제외)
    local search_paths=("/home" "/var" "/tmp" "/opt" "/srv" "/usr/local")

    for search_path in "${search_paths[@]}"; do
        if [ -d "$search_path" ]; then
            local found=$(find "$search_path" -xdev \( -nouser -o -nogroup \) -print 2>/dev/null || echo "")
            if [ -n "$found" ]; then
                while IFS= read -r file; do
                    local file_info=$(ls -lnd "$file" 2>/dev/null || echo "")
                    orphan_files="${orphan_files}${file_info}${newline}"
                    ((orphan_count++)) || true
                    raw_output="${raw_output}${file}${newline}"
                done <<< "$found"
            fi
        fi
    done || true

    # 루트 파일시스템 직접 검색 (깊이 3까지만)
    local root_found=$(find / -maxdepth 3 -xdev \( -nouser -o -nogroup \) -not -path "/home/*" -not -path "/var/*" -not -path "/tmp/*" -not -path "/opt/*" -not -path "/srv/*" -not -path "/usr/local/*" -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/run/*" -print 2>/dev/null || echo "")
    if [ -n "$root_found" ]; then
        while IFS= read -r file; do
            local file_info=$(ls -lnd "$file" 2>/dev/null || echo "")
            orphan_files="${orphan_files}${file_info}${newline}"
            ((orphan_count++)) || true
            raw_output="${raw_output}${file}${newline}"
        done <<< "$root_found"
    fi

    command_executed="find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null"

    # 최종 판정
    if [ "$orphan_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="소유자가 존재하지 않는 파일 및 디렉터리가 없음"
        command_result="${raw_output:-검색 결과 없음 (모든 파일에 소유자 존재)}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="소유자가 존재하지 않는 파일/디렉터리 ${orphan_count}개 발견"
        command_result="${orphan_files}"
    fi

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
    # Run-all 모드 확인
    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    # 결과 저장 확인
    verify_result_saved "${ITEM_ID}"


    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
