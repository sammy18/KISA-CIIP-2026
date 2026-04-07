#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-63
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 사용자 sudo 명령어 사용 제한
# @Description : sudoers 파일을 통한 특정 명령어나 권한 제한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-63"
ITEM_NAME="사용자 sudo 명령어 사용 제한"
SEVERITY="(중)"

GUIDELINE_PURPOSE="비인가자가 관리자 권한을 남용하여 시스템 손상, 악성 코드 실행, 민감한 데이터 유출 등의 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="sudo 명령어 접근을 제한하지 않을 경우, 비인가자가 관리자 권한으로 허가되지 않은 명령어를 사용하여 루트 권한 오용, 악성 코드 실행, 데이터 유출 등의 시도를 할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우"
GUIDELINE_CRITERIA_BAD="/etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우"
GUIDELINE_REMEDIATION="/etc/sudoers 파일 소유자 및 권한 변경 설정"

diagnose() {
    local status="미진단"
    local diagnosis_result="unknown"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # sudo 명령어 접근 관리 확인

    local sudo_installed=false
    local sudoers_issues=false
    local issue_details=""

    # 1) sudo 설치 여부 확인
    if command -v sudo >/dev/null 2>&1; then
        sudo_installed=true
    fi

    if [ "$sudo_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="sudo가 설치되지 않음 (root만 권한 관리)"
        local cmd_check=$(command -v sudo 2>/dev/null || echo "sudo command not found")
        local rpm_check=$(rpm -qa | grep -i sudo 2>/dev/null || echo "sudo packages not found")
        command_result="[Command: command -v sudo]${newline}${cmd_check}${newline}${newline}[Command: rpm -qa | grep sudo]${newline}${rpm_check}"
        command_executed="command -v sudo; rpm -qa | grep -i sudo"
    else
        # 2) sudoers 파일 확인
        local sudoers_files=("/etc/sudoers" "/etc/sudoers.d/*")

        # 2-1) sudoers 파일 권한 확인 (RedHat: stat 사용)
        for sudoers_file in /etc/sudoers /etc/sudoers.d/*; do
            if [ -f "$sudoers_file" ]; then
                local perms=$(stat -c "%a" "$sudoers_file" 2>/dev/null || echo "0000")
                local owner=$(stat -c "%U" "$sudoers_file" 2>/dev/null || echo "unknown")
                local group=$(stat -c "%G" "$sudoers_file" 2>/dev/null || echo "unknown")

                # 권한이 0440이거나 소유자가 root:root가 아닌 경우
                if [ "$perms" != "0440" ]; then
                    sudoers_issues=true
                    issue_details="${issue_details}${sudoers_file} 권한 ${perms} (0440 권장), "
                fi

                if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
                    sudoers_issues=true
                    issue_details="${issue_details}${sudoers_file} 소유자 ${owner}:${group} (root:root 권장), "
                fi
            fi
        done || true

        # 2-2) 취약한 sudoers 규칙 확인
        # ALL 권한을 가진 사용자/그룹 확인
        local all_privilege=$(grep -v "^#" /etc/sudoers 2>/dev/null | grep -E "ALL=\(ALL\) ALL|ALL=\(ALL:ALL\) ALL")
        if [ -n "$all_privilege" ]; then
            # root는 제외
            local non_root_all=$(echo "$all_privilege" | grep -v "root")
            if [ -n "$non_root_all" ]; then
                sudoers_issues=true
                issue_details="${issue_details}모든 권한을 가진 비-root 사용자: ${non_root_all}, "
            fi
        fi

        # 암호 없이 sudo 사용 가능한 규칙 확인 (NOPASSWD)
        local nopasswd_rules=$(grep -v "^#" /etc/sudoers 2>/dev/null | grep -i "NOPASSWD")
        if [ -n "$nopasswd_rules" ]; then
            sudoers_issues=true
            issue_details="${issue_details}암호 없는 sudo 규칙: ${nopasswd_rules}, "
        fi

        # 최종 판정
        if [ "$sudoers_issues" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="sudoers 설정에 보안 문제 존재: ${issue_details%, }"
            local grep_sudoers=$(grep -v '^#' /etc/sudoers 2>/dev/null | head -20 || echo "sudoers not readable")
            local ls_sudoers_d=$(ls -la /etc/sudoers.d/ 2>/dev/null || echo "sudoers.d not readable")
            command_result="${issue_details%, }${newline}${newline}[Command: grep -v '^#' /etc/sudoers]${newline}${grep_sudoers}${newline}${newline}[Command: ls -la /etc/sudoers.d/]${newline}${ls_sudoers_d}"
            command_executed="grep -v '^#' /etc/sudoers 2>/dev/null | head -20; ls -la /etc/sudoers.d/ 2>/dev/null"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="sudoers 설정이 안전하게 구성됨 (권한 0440, root:root)"
            local stat_sudoers=$(stat -c '%a:%U:%G' /etc/sudoers 2>/dev/null)
            local grep_sudoers=$(grep -v '^#' /etc/sudoers 2>/dev/null | head -20 || echo "sudoers not readable")
            command_result="sudoers 파일 정보:${newline}${stat_sudoers}${newline}${newline}[sudoers 규칙]${newline}${grep_sudoers}"
            command_executed="stat -c '%a:%U:%G' /etc/sudoers; grep -v '^#' /etc/sudoers 2>/dev/null | head -20"
        fi
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

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
