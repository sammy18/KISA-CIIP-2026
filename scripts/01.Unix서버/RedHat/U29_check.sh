#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-29
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : LPD 설정 확인
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


ITEM_ID="U-29"
ITEM_NAME="hosts.lpd 파일 소유자 및 권한 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="잘못설정된UMASK값으로인해신규파일에대한권한이과도하게부여되는것을방지하기위함"
GUIDELINE_THREAT="잘못설정된UMASK로인해파일및디렉터리생성시과도한권한이부여되어무단액세스및데이터 유출의위험이존재함"
GUIDELINE_CRITERIA_GOOD="UMASK값이022이상으로설정된경우"
GUIDELINE_CRITERIA_BAD="UMASK값이022미만으로설정된경우"
GUIDELINE_REMEDIATION="설정파일에UMASK값을022로설정"

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
    # /etc/hosts.lpd 파일 소유자 및 권한 설정 확인 (LPD 라인 프린터 데몬)

    local hosts_lpd_exists=0
    local hosts_lpd_secure=0
    local hosts_lpd_details=""

    # Capture ls and systemctl output
    local hosts_lpd_ls=$(ls -l /etc/hosts.lpd 2>&1)
    local cups_status=$(systemctl status cups 2>/dev/null | head -5 || echo "CUPS not found")
    command_result="[Command: ls -l /etc/hosts.lpd]${newline}${hosts_lpd_ls}${newline}${newline}[Command: systemctl status cups]${newline}${cups_status}"

    # /etc/hosts.lpd 파일 확인
    if [ -f "/etc/hosts.lpd" ]; then
        ((hosts_lpd_exists++))
        local perms=$(stat -c "%a" "/etc/hosts.lpd" 2>/dev/null)
        local owner=$(stat -c "%U:%G" "/etc/hosts.lpd" 2>/dev/null)

        # 보안 설정 확인: root:root 600 또는 400
        if [ "$owner" = "root:root" ]; then
            if [ "$perms" = "600" ] || [ "$perms" = "400" ]; then
                ((hosts_lpd_secure++))
                hosts_lpd_details="/etc/hosts.lpd: 존재, 소유자: ${owner}, 권한: ${perms} (보안 양호)"
            else
                hosts_lpd_details="/etc/hosts.lpd: 존재, 소유자: ${owner}, 권한: ${perms} (권한 취약 - 600 또는 400 권장)"
            fi
        else
            hosts_lpd_details="/etc/hosts.lpd: 존재, 소유자: ${owner} (root:root 아님 - 취약)"
        fi
    fi

    # LPD 서비스 실행 여부 확인
    local lpd_running=0
    if command -v lpstat &>/dev/null || systemctl is-active --quiet cups 2>/dev/null || systemctl is-active --quiet lpd 2>/dev/null; then
        ((lpd_running++))
    fi

    # 결과 판정
    if [ "$hosts_lpd_exists" -eq 0 ]; then
        if [ "$lpd_running" -eq 0 ]; then
            # LPD 서비스 미사용 및 파일 없음
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="LPD 서비스 미사용 및 hosts.lpd 파일 없음 (보안 양호)"
            command_executed="ls -l /etc/hosts.lpd 2>/dev/null; systemctl status cups lpd 2>/dev/null"
        else
            # LPD 서비스 사용 중이나 hosts.lpd 없음 (최신 시스템은 CUPS 사용)
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="LPD/CUPS 서비스 사용 중이나 hosts.lpd 파일 없음 (최신 시스템에서는 정상)"
            command_executed="ls -l /etc/hosts.lpd 2>/dev/null; systemctl status cups 2>/dev/null"
        fi
    else
        # hosts.lpd 파일 존재
        if [ "$hosts_lpd_secure" -gt 0 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="${hosts_lpd_details}"
            command_executed="stat -c '%a:%U:%G' /etc/hosts.lpd 2>/dev/null"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="${hosts_lpd_details} (권한 600/400 및 root:root 소유자 필요)"
            command_executed="stat -c '%a:%U:%G' /etc/hosts.lpd 2>/dev/null"
        fi
    fi

    #echo ""
    #echo "진단 결과: ${status}"
    #echo "판정: ${diagnosis_result}"
    #echo "설명: ${inspection_summary}"
    #echo ""

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
