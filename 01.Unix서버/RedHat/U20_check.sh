#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-20
# @Category    : Unix Server
# @Platform    : RedHat
# @Severity    : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : root:root 600 확인
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


ITEM_ID="U-20"
ITEM_NAME="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="/etc/(x)inetd.conf 파일을 관리자만 제어하여 비인가자들의 임의적인 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="/etc/(x)inetd.conf 파일에 소유자 외 쓰기 권한이 부여된 경우, 일반 사용자 권한으로 해당 파일에 등록된 서비스를 변조하거나 악의적인 프로그램(서비스)을 등록할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/(x)inetd.conf 파일 소유자 및 권한 변경 설정"

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
    # /etc/(x)inetd.conf 파일 소유자 및 권한 설정 확인 (RedHat: xinetd 사용)

    local target_file=""
    local is_secure=false
    local details=""

    # RedHat: xinetd.conf 우선 확인 (RedHat 표준)
    if [ -f "/etc/xinetd.conf" ]; then
        target_file="/etc/xinetd.conf"
    elif [ -f "/etc/inetd.conf" ]; then
        target_file="/etc/inetd.conf"
    fi

    # Capture command outputs
    local ls_output=$(ls -l /etc/inetd.conf /etc/xinetd.conf 2>&1)
    local stat_output=""

    # 파일 존재 확인
    if [ -z "$target_file" ] || [ ! -f "$target_file" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="xinetd 설정 파일 없음 (서비스 미사용)"
        command_result="[Command: ls -l /etc/inetd.conf /etc/xinetd.conf]${newline}${ls_output}"
        command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf 2>&1"
    else
        # RedHat: stat -c 사용 가능
        if [ -x "$(command -v stat)" ]; then
            stat_output=$(stat -c "%a:%U:%G" "$target_file" 2>/dev/null)
        else
            stat_output=$(ls -l "$target_file" 2>/dev/null | awk '{print $1":"$3":"$4}')
        fi

        # 파일 권한 확인 (RedHat: stat -c 사용)
        local file_perms=$(stat -c "%a" "$target_file" 2>/dev/null || echo "0000")
        local file_owner=$(stat -c "%U" "$target_file" 2>/dev/null || echo "unknown")
        local file_group=$(stat -c "%G" "$target_file" 2>/dev/null || echo "unknown")

        # 소유자 및 권한 확인 (권한이 600 이하이면 양호)
        if [ "$file_owner" = "root" ] && [ "$file_perms" -le 600 ] 2>/dev/null; then
            is_secure=true
            details="파일: $target_file, 권한: $file_perms, 소유자: ${file_owner}:${file_group}"
        else
            details="파일: $target_file, 권한: $file_perms, 소유자: ${file_owner}:${file_group}"
        fi

        # 최종 판정
        if [ "$is_secure" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="(x)inetd.conf 보안 설정 적절 ($details)"
            command_result="[Command: ls -l /etc/inetd.conf /etc/xinetd.conf]${newline}${ls_output}${newline}${newline}[Command: stat -c '%a:%U:%G' $target_file]${newline}${stat_output}"
            command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf; stat -c '%a:%U:%G' $target_file"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="(x)inetd.conf 보안 설정 부적절 ($details)"
            command_result="[Command: ls -l /etc/inetd.conf /etc/xinetd.conf]${newline}${ls_output}${newline}${newline}[Command: stat -c '%a:%U:%G' $target_file]${newline}${stat_output}"
            command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf; stat -c '%a:%U:%G' $target_file"
        fi
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
