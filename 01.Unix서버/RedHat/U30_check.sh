#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-30
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 중
# @Title       : UMASK 설정 관리
# @Description : UMASK 022 또는 027 확인
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


ITEM_ID="U-30"
ITEM_NAME="UMASK 설정 관리"
SEVERITY="중"

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
    # UMASK 022 또는 027 확인

    local is_secure=false
    local umask_details=""
    local config_files_checked=0

    # UMASK 설정 확인 대상 파일 목록
    local umask_files=(
        "/etc/profile"
        "/etc/bash.bashrc"
        "/etc/profile.d/*.sh"
        "/root/.bashrc"
        "/root/.profile"
        "/etc/default/login"
    )

    # 각 설정 파일에서 UMASK 값 추출
    declare -A found_umasks

    for umask_file in "${umask_files[@]}"; do
        # 와일드카드 처리
        for actual_file in $umask_file 2>/dev/null; do
            if [ -f "$actual_file" ]; then
                ((config_files_checked++))
                # umask 또는 UMASK 키워드로 검색 (주석 제외)
                local umask_value=$(grep "^[[:space:]]*umask" "$actual_file" 2>/dev/null | grep -v "^[[:space:]]*#" | awk '{print $2}' | head -1)

                if [ -n "$umask_value" ]; then
                    found_umasks["$actual_file"]="$umask_value"
                fi
            fi
        done
    done

    # 발견된 UMASK 값 검증
    local insecure_found=false
    local secure_found=false
    local all_umask_values=""

    # Capture raw grep output for all umask settings
    local umask_grep=$(grep -h 'umask' /etc/profile /etc/bash.bashrc /root/.bashrc ~/.bashrc 2>/dev/null | grep -v "^#" | grep -v "^$")
    command_result="[Command: grep -h 'umask' /etc/profile /etc/bash.bashrc /root/.bashrc ~/.bashrc]${newline}${umask_grep}"

    for file in "${!found_umasks[@]}"; do
        local value="${found_umasks[$file]}"
        all_umask_values="${all_umask_values}${file}: ${value}, "

        # UMASk 값 검증 (022, 027 권장)
        if [ "$value" = "022" ] || [ "$value" = "027" ]; then
            secure_found=true
        else
            insecure_found=true
        fi
    done

    # 최종 판정
    if [ $config_files_checked -eq 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="UMASK 설정 파일을 찾을 수 없음 (시스템 기본값 확인 필요)"
        command_executed="grep -h 'umask' /etc/profile /etc/bash.bashrc /root/.bashrc 2>/dev/null"
    elif [ "$insecure_found" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="부적절한 UMASK 설정 존재: ${all_umask_values%, } (022 또는 027 권장)"
        command_executed="grep -h '^umask' /etc/profile /etc/bash.bashrc /root/.bashrc 2>/dev/null"
    elif [ "$secure_found" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="적절한 UMASK 설정됨: ${all_umask_values%, } (022 또는 027)"
        command_executed="grep -h '^umask' /etc/profile /etc/bash.bashrc /root/.bashrc 2>/dev/null"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="UMASK 설정 없음 (기본값 확인 필요: 보통 022)"
        command_executed="grep -h 'umask' /etc/profile /etc/bash.bashrc /root/.bashrc 2>/dev/null"
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
