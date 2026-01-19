#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-15
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리를 찾아 제거 또는 관리
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

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

    # 진단 로직: 소유자가 존재하지 않는 파일 및 디렉터리 확인
    # find / -nouser 또는 find / -nouser -type f / -type d 사용

    local orphaned_files=""
    local orphaned_dirs=""
    local orphaned_file_count=0
    local orphaned_dir_count=0

    # 소유자가 없는 파일 확인 (시스템 디렉토리만 검색, 성능 이슈 방지)
    local system_dirs=("/etc" "/home" "/var" "/usr" "/opt" "/root")

    for dir in "${system_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # 소유자가 없는 파일 검색
            while IFS= read -r file; do
                if [ -n "$file" ]; then
                    ((orphaned_file_count++))
                    orphaned_files="${orphaned_files}${file}, "
                fi
            done < <(find "$dir" -xdev -nouser -type f 2>/dev/null | head -20)

            # 소유자가 없는 디렉토리 검색
            while IFS= read -r dir_path; do
                if [ -n "$dir_path" ]; then
                    ((orphaned_dir_count++))
                    orphaned_dirs="${orphaned_dirs}${dir_path}, "
                fi
            done < <(find "$dir" -xdev -nouser -type d 2>/dev/null | head -20)
        fi
    done

    # Build raw command output
    local raw_output=""
    if [ "$orphaned_file_count" -gt 0 ]; then
        raw_output="${raw_output}[Files with no owner]${newline}${orphaned_files%, }${newline}"
    fi
    if [ "$orphaned_dir_count" -gt 0 ]; then
        raw_output="${raw_output}[Directories with no owner]${newline}${orphaned_dirs%, }"
    fi
    if [ -z "$raw_output" ]; then
        raw_output="No orphaned files or directories found"
    fi
    command_result="[Command: find /etc /home /var /usr /opt /root -xdev -nouser]${newline}${raw_output}"

    if [ "$orphaned_file_count" -eq 0 ] && [ "$orphaned_dir_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="소유자가 존재하지 않는 파일 및 디렉터리가 발견되지 않음"
        command_executed="find /etc /home /var /usr /opt /root -xdev -nouser 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="소유자가 존재하지 않는 파일: ${orphaned_file_count}개, 디렉터리: ${orphaned_dir_count}개 발견"

        # 결과 조합
        local result_details=""
        if [ "$orphaned_file_count" -gt 0 ]; then
            result_details="파일 (${orphaned_file_count}개): ${orphaned_files%, }"
        fi
        if [ "$orphaned_dir_count" -gt 0 ]; then
            if [ -n "$result_details" ]; then
                result_details="${result_details} | "
            fi
            result_details="${result_details}디렉터리 (${orphaned_dir_count}개): ${orphaned_dirs%, }"
        fi

        # command_result already contains raw output
        command_executed="find /etc /home /var /usr /opt /root -xdev -nouser 2>/dev/null"
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
