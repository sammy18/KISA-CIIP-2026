#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.2
# @Last Updated: 2026-04-23
# ============================================================================
# [점검 항목 상세]
# @ID          : U-15
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리 확인 (고아 파일 탐지)
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

diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    local is_secure=true
    local orphan_files=""
    local orphan_count=0

    # /etc/passwd에 존재하는 UID 목록 추출
    local valid_uids=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort -u)

    # 고아 파일(소유자가 /etc/passwd에 없는 파일) 탐지
    # AIX: find -nouser 사용 (GNU find 및 AIX find 모두 지원)
    local search_dirs=("/etc" "/usr" "/var" "/opt" "/home" "/tmp" "/")

    for search_dir in "${search_dirs[@]}"; do
        if [ -d "$search_dir" ]; then
            local found=$(find "$search_dir" -nouser -type f -o -nouser -type d 2>/dev/null | head -50 || echo "")
            if [ -n "$found" ]; then
                while IFS= read -r file_path; do
                    [ -z "$file_path" ] && continue
                    local file_uid=$(perl -e 'print +(stat shift)[4]' "$file_path" 2>/dev/null || echo "unknown")
                    orphan_files="${orphan_files}${file_path} (UID: ${file_uid}), "
                    ((orphan_count++)) || true
                done <<< "$found"
            fi
        fi
    done || true

    # 결과 정리
    if [ "$orphan_count" -eq 0 ]; then
        is_secure=true
    else
        is_secure=false
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="소유자가 존재하지 않는 파일 및 디렉터리가 없습니다."
        local find_raw=$(find / -nouser -type f -o -nouser -type d 2>/dev/null | head -20 || echo "No orphan files found")
        command_result="[Command: find / -nouser]${newline}${find_raw}"
        command_executed="find / -nouser -type f -o -nouser -type d 2>/dev/null | head -50"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="소유자가 존재하지 않는 파일/디렉터리 ${orphan_count}개 발견: ${orphan_files%, }"
        command_result="${orphan_files%, }"
        command_executed="find / -nouser -type f -o -nouser -type d 2>/dev/null | head -50"
    fi

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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    check_disk_space

    diagnose

    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
