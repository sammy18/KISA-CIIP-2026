#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-12
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 하
# @Title       : 세션 종료시간 설정
# @Description : TMOUT 또는 /etc/profile 설정 확인
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


ITEM_ID="U-12"
ITEM_NAME="세션 종료시간 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의고의또는실수로시스템에계정이접속된상태로방치됨을차단하기위함"
GUIDELINE_THREAT="Sessiontimeout값이설정되지않을경우,유휴시간내비인가자가시스템에접근하여불필요한내부정보를노출할위험이존재함"
GUIDELINE_CRITERIA_GOOD="Session Timeout이600초(10분)이하로설정된경우"
GUIDELINE_CRITERIA_BAD="Session Timeout이600초(10분)이하로설정되지않은경우"
GUIDELINE_REMEDIATION="600초(10분)동안입력이없는경우접속된Session을끊도록설정"

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

    # 세션 종료시간(TMOUT) 설정 확인
    # 양호: TMOUT이 600초(10분) 이하로 설정된 경우
    # 취약: TMOUT이 설정되지 않았거나 600초 초과인 경우

    local timeout_found=false
    local timeout_value=""
    local timeout_source=""
    local config_files=""

    # 최대 TMOUT값 추적 (여러 파일에서 설정된 경우 가장 작은 값 사용)
    local min_tmout=999999
    local tmout_sources=()

    # 1) /etc/profile 확인 (시스템 전역 설정)
    if [ -f /etc/profile ]; then
        local etc_profile_tmout=$(grep -E "^[[:space:]]*TMOUT=" /etc/profile 2>/dev/null | grep -v "^[[:space:]]*#" | tail -1 | sed 's/.*TMOUT=\([0-9]*\).*/\1/' || echo "")
        if [ -n "$etc_profile_tmout" ] && [[ "$etc_profile_tmout" =~ ^[0-9]+$ ]]; then
            timeout_found=true
            if [ "$etc_profile_tmout" -lt "$min_tmout" ]; then
                min_tmout=$etc_profile_tmout
            fi
            tmout_sources+=("/etc/profile: TMOUT=${etc_profile_tmout}")
            config_files="${config_files}/etc/profile: TMOUT=${etc_profile_tmout}${newline}"
        fi
    fi

    # 2) /etc/bashrc 확인 (시스템 전역 bash 설정)
    if [ -f /etc/bashrc ]; then
        local etc_bashrc_tmout=$(grep -E "^[[:space:]]*TMOUT=" /etc/bashrc 2>/dev/null | grep -v "^[[:space:]]*#" | tail -1 | sed 's/.*TMOUT=\([0-9]*\).*/\1/' || echo "")
        if [ -n "$etc_bashrc_tmout" ] && [[ "$etc_bashrc_tmout" =~ ^[0-9]+$ ]]; then
            timeout_found=true
            if [ "$etc_bashrc_tmout" -lt "$min_tmout" ]; then
                min_tmout=$etc_bashrc_tmout
            fi
            tmout_sources+=("/etc/bashrc: TMOUT=${etc_bashrc_tmout}")
            config_files="${config_files}/etc/bashrc: TMOUT=${etc_bashrc_tmout}${newline}"
        fi
    fi

    # 3) /etc/profile.d/ 디렉토리 내 *.sh 파일 확인
    if [ -d /etc/profile.d ]; then
        local profile_d_files=$(find /etc/profile.d -name "*.sh" -type f 2>/dev/null || echo "")
        for profile_file in $profile_d_files; do
            local profile_d_tmout=$(grep -E "^[[:space:]]*TMOUT=" "$profile_file" 2>/dev/null | grep -v "^[[:space:]]*#" | tail -1 | sed 's/.*TMOUT=\([0-9]*\).*/\1/' || echo "")
            if [ -n "$profile_d_tmout" ] && [[ "$profile_d_tmout" =~ ^[0-9]+$ ]]; then
                timeout_found=true
                if [ "$profile_d_tmout" -lt "$min_tmout" ]; then
                    min_tmout=$profile_d_tmout
                fi
                tmout_sources+=("${profile_file}: TMOUT=${profile_d_tmout}")
                config_files="${config_files}${profile_file}: TMOUT=${profile_d_tmout}${newline}"
            fi
        done
    fi

    # 4) 현재 환경에서 TMOUT 변수 확인 (실제 적용 값)
    if [ -n "${TMOUT:-}" ]; then
        timeout_found=true
        if [[ "$TMOUT" =~ ^[0-9]+$ ]]; then
            if [ "$TMOUT" -lt "$min_tmout" ]; then
                min_tmout=$TMOUT
            fi
            tmout_sources+=("현재 환경: TMOUT=${TMOUT}")
            config_files="${config_files}현재 환경변수: TMOUT=${TMOUT}${newline}"
        fi
    fi

    # 5) 사용자별 설정 파일 확인 (현재 사용자)
    local home="${HOME:-}"
    if [ -n "$home" ]; then
        # ~/.bash_profile 확인
        if [ -f "$home/.bash_profile" ]; then
            local bash_profile_tmout=$(grep -E "^[[:space:]]*TMOUT=" "$home/.bash_profile" 2>/dev/null | grep -v "^[[:space:]]*#" | tail -1 | sed 's/.*TMOUT=\([0-9]*\).*/\1/' || echo "")
            if [ -n "$bash_profile_tmout" ] && [[ "$bash_profile_tmout" =~ ^[0-9]+$ ]]; then
                timeout_found=true
                if [ "$bash_profile_tmout" -lt "$min_tmout" ]; then
                    min_tmout=$bash_profile_tmout
                fi
                tmout_sources+=("~/.bash_profile: TMOUT=${bash_profile_tmout}")
                config_files="${config_files}~/.bash_profile: TMOUT=${bash_profile_tmout}${newline}"
            fi
        fi

        # ~/.bashrc 확인
        if [ -f "$home/.bashrc" ]; then
            local bashrc_tmout=$(grep -E "^[[:space:]]*TMOUT=" "$home/.bashrc" 2>/dev/null | grep -v "^[[:space:]]*#" | tail -1 | sed 's/.*TMOUT=\([0-9]*\).*/\1/' || echo "")
            if [ -n "$bashrc_tmout" ] && [[ "$bashrc_tmout" =~ ^[0-9]+$ ]]; then
                timeout_found=true
                if [ "$bashrc_tmout" -lt "$min_tmout" ]; then
                    min_tmout=$bashrc_tmout
                fi
                tmout_sources+=("~/.bashrc: TMOUT=${bashrc_tmout}")
                config_files="${config_files}~/.bashrc: TMOUT=${bashrc_tmout}${newline}"
            fi
        fi
    fi

    # Build raw command output for all checked files
    local raw_output=""
    for source in "${tmout_sources[@]}"; do
        raw_output="${raw_output}${source}${newline}"
    done
    command_result="[Checked TMOUT configurations]${newline}${raw_output}"

    # 최종 판정
    if [ "$timeout_found" = false ] || [ "$min_tmout" -eq 999999 ]; then
        # TMOUT이 설정되지 않음
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="세션 종료시간(TMOUT)이 설정되지 않음"
        # command_result already contains raw output
        command_executed="grep -E 'TMOUT=' /etc/profile /etc/bashrc /etc/profile.d/*.sh ~/.bash_profile ~/.bashrc 2>/dev/null"
    elif [ "$min_tmout" -le 600 ]; then
        # TMOUT이 600초(10분) 이하로 설정됨 (양호)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="세션 종료시간이 적절하게 설정됨: ${min_tmout}초"
        # command_result already contains raw output
        command_executed="grep -E 'TMOUT=' /etc/profile /etc/bashrc /etc/profile.d/*.sh"
    else
        # TMOUT이 600초 초과로 설정됨 (취약)
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="세션 종료시간이 600초(10분)을 초과함: ${min_tmout}초 (600초 이하 권장)"
        # command_result already contains raw output
        command_executed="grep -E 'TMOUT=' /etc/profile /etc/bashrc /etc/profile.d/*.sh"
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
