#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-34
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 확인
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


ITEM_ID="U-34"
ITEM_NAME="Finger 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="무차별 대입 공격(Brute-force)을 방지하여 계정 잠금 및 서비스 거부(DoS) 상태를 방지하기 위함"
GUIDELINE_THREAT="로그온 시도 횟수 제한이 미흡할 경우, 공격자가 무차별 대입 공격을 통해 계정을 잠금시키거나, 서비스 거부 상태로 만들어 시스템 가용성을 저해할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그온 시도 횟수 제한(deny)이 5회 이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="로그온 시도 횟수 제한이 설정되어 있지 않거나, deny 값이 5회를 초과하는 경우"
GUIDELINE_REMEDIATION="/etc/security/faillock.conf 파일 또는 PAM 설정 파일(/etc/pam.d/common-auth 등)에서 deny 값을 5 이하로 설정"

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

    # Finger 서비스 비활성화 확인
    # 양호: Finger 서비스가 비활성화된 경우
    # 취약: Finger 서비스가 활성화된 경우

    local finger_running=false
    local finger_info=""
    local active_sources=()

    # 1) systemd 서비스 확인 (fingerd, cfingerd, in.fingerd)
    local finger_services=("fingerd" "cfingerd" "in.fingerd" "finger")
    for svc in "${finger_services[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}.service"; then
            local svc_state=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            local svc_enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")
            finger_info="${finger_info}${svc}: ${svc_state} (${svc_enabled})${newline}"

            if [ "$svc_state" = "active" ]; then
                finger_running=true
                active_sources+=("${svc} 서비스 실행 중")
            fi
        fi
    done

    # 2) xinetd 기반 서비스 확인
    local xinetd_files=("/etc/xinetd.d/finger" "/etc/xinetd.d/fingerd")
    for xinetd_file in "${xinetd_files[@]}"; do
        if [ -f "$xinetd_file" ]; then
            local disabled=$(grep -i "disable" "$xinetd_file" | grep -v "^[[:space:]]*#" | awk '{print $2}')
            finger_info="${finger_info}${xinetd_file}: disable=${disabled}${newline}"

            if [ "$disabled" = "no" ]; then
                finger_running=true
                active_sources+=("${xinetd_file}에서 활성화됨")
            fi
        fi
    done

    # 3) inetd 기반 서비스 확인 (레거시 시스템)
    if [ -f /etc/inetd.conf ]; then
        local inetd_finger=$(grep -E "^(finger|fingerd)" /etc/inetd.conf | grep -v "^[[:space:]]*#" || echo "")
        if [ -n "$inetd_finger" ]; then
            finger_running=true
            active_sources+=("inetd.conf에서 finger 활성화됨")
            finger_info="${finger_info}/etc/inetd.conf: ${inetd_finger}${newline}"
        fi
    fi

    # 4) 포트 확인 (Finger는 TCP 79 사용)
    if command -v ss &>/dev/null; then
        local finger_port=$(ss -tuln | grep ":79 " || echo "")
        if [ -n "$finger_port" ]; then
            finger_running=true
            active_sources+=("포트 79(TCP) 활성화됨")
            finger_info="${finger_info}포트 79(TCP)에서 Finger 서비스 감지${newline}"
        fi
    fi

    # 5) finger 명령어 설치 여부 확인 (단순 설치만으로는 활성화로 간주하지 않음)
    if command -v finger &>/dev/null; then
        finger_info="${finger_info}finger 명령어: 설치됨 (서비스 상태 확인 필요)${newline}"
    fi

    # 최종 판정
    if [ "$finger_running" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Finger 서비스 활성화됨: ${active_sources[*]}"
        command_result="${finger_info}"
        command_executed="systemctl is-active fingerd cfingerd; cat /etc/xinetd.d/finger* 2>/dev/null; ss -tuln | grep ':79 '"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Finger 서비스 비활성화됨"
        command_result="${finger_info}"
        command_executed="systemctl is-active fingerd cfingerd; cat /etc/xinetd.d/finger* 2>/dev/null; ss -tuln | grep ':79 '"
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
