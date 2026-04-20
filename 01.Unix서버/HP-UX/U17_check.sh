#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-17
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : /sbin/rc*.d/* 권한 확인
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


ITEM_ID="U-17"
ITEM_NAME="시스템 시작 스크립트 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="시스템 시작 스크립트 파일을 관리자만 제어할 수 있게하여 비인가자들의 임의적인 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="시스템 시작 스크립트 파일의 소유권 및 권한 설정이 미흡할 경우, 비인가자가 스크립트의 내용 변경 등을 통해 시스템 침입 등 악용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우"
GUIDELINE_CRITERIA_BAD="시스템 시작 스크립트 파일의 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여된 경우"
GUIDELINE_REMEDIATION="시스템 시작 스크립트 파일 소유자 및 권한 변경 설정"

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
    # HP-UX 시스템 시작 스크립트 점검: /sbin/rc*.d/*

    local init_script_dir="/sbin/rc.d"
    local vulnerable_files=""
    local vulnerable_count=0
    local script_count=0

    # HP-UX 시스템 시작 스크립트 검색
    local raw_output=""
    if [ -d "$init_script_dir" ]; then
        # rc*.d 디렉터리 목록 가져오기 (rc0.d, rc1.d, rc2.d, rc3.d 등)
        local rc_dirs=$(find /sbin -type d -name "rc*.d" 2>/dev/null || true)

        for rc_dir in $rc_dirs; do
            if [ -d "$rc_dir" ]; then
                # 디렉터리 내의 모든 파일/심볼릭 링크 점검
                local dir_files=$(find "$rc_dir" -type f -o -type l 2>/dev/null | head -50 || true)
                raw_output="${raw_output}${dir_files}"$'\n'

                while IFS= read -r file; do
                    if [ -n "$file" ]; then
                        ((script_count++)) || true

                        # HP-UX: perl 사용하여 권한 및 소유자 확인
                        local perms=$(perl -e '@s=stat(shift); printf "%04o\n", $s[2] & 07777' "$file" 2>/dev/null)
                        local owner=$(perl -e '($dev,$ino,$mode,$nlink,$uid,$gid)=stat(shift); print getpwuid($uid)' "$file" 2>/dev/null)

                        # 심볼릭 링크인 경우 대상 파일 확인
                        local is_link=0
                        if [ -L "$file" ]; then
                            is_link=1
                            local target=$(readlink "$file" 2>/dev/null || echo "")
                            if [ -n "$target" ]; then
                                # 절대 경로 변환
                                if [[ "$target" != /* ]]; then
                                    target=$(dirname "$file")/$target
                                fi
                                target=$(readlink -f "$target" 2>/dev/null || echo "$target")
                                if [ -e "$target" ]; then
                                    perms=$(perl -e '@s=stat(shift); printf "%04o\n", $s[2] & 07777' "$target" 2>/dev/null)
                                    owner=$(perl -e '($dev,$ino,$mode,$nlink,$uid,$gid)=stat(shift); print getpwuid($uid)' "$target" 2>/dev/null)
                                fi
                            fi
                        fi

                        # 취약 판단: 소유자가 root가 아니거나, others 쓰기 권한이 있음
                        if [ "$owner" != "root" ]; then
                            ((vulnerable_count++)) || true
                            vulnerable_files="${vulnerable_files}${file} (소유자: ${owner}, 권한: ${perms}), "
                        else
                            # others 쓰기 권한 확인 (마지막 숫자)
                            local last_octet=$(( perms % 10 ))
                            if [ "$last_octet" -ge 2 ] 2>/dev/null; then
                                ((vulnerable_count++)) || true
                                vulnerable_files="${vulnerable_files}${file} (소유자: root, 권한: ${perms}, others 쓰기 허용), "
                            fi
                        fi
                    fi
                done <<< "$dir_files" || true
            fi
        done
    else
        raw_output="시스템 시작 스크립트 디렉터리(${init_script_dir})가 존재하지 않음"
    fi

    # 결과 판정
    if [ "$vulnerable_count" -eq 0 ]; then
        if [ "$script_count" -eq 0 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="시스템 시작 스크립트 파일 없음 (최신 시스템)"
            command_result="${raw_output}"
            command_executed="find /sbin -type d -name 'rc*.d' 2>/dev/null"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="시스템 시작 스크립트 ${script_count}개 파일 모두 root 소유, others 쓰기 권한 없음"
            command_result="${raw_output}"
            command_executed="find /sbin -type d -name 'rc*.d' -exec find {} -type f -o -type l \\; 2>/dev/null"
        fi
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 시스템 시작 스크립트 ${vulnerable_count}개 발견: ${vulnerable_files%, }"
        command_result="${raw_output}"
        command_executed="find /sbin -type d -name 'rc*.d' -exec find {} -type f -o -type l \\; 2>/dev/null"
    fi

    # 결과 저장
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

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
