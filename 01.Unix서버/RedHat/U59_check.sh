#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-59
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : 안전한 SNMP 버전 사용
# @Description : SNMP v3 사용 확인
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


ITEM_ID="U-59"
ITEM_NAME="안전한 SNMP 버전 사용"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전한SNMP버전사용으로전송되는데이터를보호하기위함"
GUIDELINE_THREAT="SNMP버전이기준보다낮을경우,응답패킷이평문으로전송되어스니핑위험이존재함"
GUIDELINE_CRITERIA_GOOD="SNMP서비스를v3이상으로사용하는경우"
GUIDELINE_CRITERIA_BAD="SNMP서비스를v2이하로사용하는경우"
GUIDELINE_REMEDIATION="Ÿ SNMP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ SNMP서비스사용시SNMP버전을v3이상으로적용하도록설정"

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
    # SNMP v3 사용 확인

    local snmpd_installed=false
    local snmp_running=false
    local snmp_version=""
    local config_details=""

    # 1) SNMP 서비스 설치 여부 확인
    if command -v snmpd >/dev/null 2>&1 || [ -f /etc/snmp/snmpd.conf ]; then
        snmpd_installed=true
    fi

    # 2) SNMP 서비스 실행 여부 확인
    if [ "$snmpd_installed" = true ]; then
        if command -v systemctl >/dev/null 2>&1; then
            local service_status=$(systemctl is-active snmpd 2>/dev/null || echo "inactive")
            if [ "$service_status" = "active" ] || [ "$service_status" = "running" ]; then
                snmp_running=true
            fi
        fi
    fi

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        local raw_snmpd_check=$(which snmpd 2>&1; ls /etc/snmp/snmpd.conf 2>&1)
        command_result="[Command: which snmpd; ls /etc/snmp/snmpd.conf 2>/dev/null]${newline}${raw_snmpd_check}"
        command_executed="which snmpd; ls /etc/snmp/snmpd.conf 2>/dev/null"
    elif [ "$snmp_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되어 있으나 비활성화됨"
        local raw_snmp_status=$(systemctl is-active snmpd 2>&1)
        command_result="[Command: systemctl is-active snmpd 2>/dev/null]${newline}${raw_snmp_status}"
        command_executed="systemctl is-active snmpd 2>/dev/null"
    else
        # 3) SNMP 버전 설정 확인 (snmpd.conf)
        local snmp_conf="/etc/snmp/snmpd.conf"
        if [ -f "$snmp_conf" ]; then
            # SNMP v1/v2c 사용 여부 확인
            if grep -qi "com2sec" "$snmp_conf" 2>/dev/null; then
                snmp_version="v1/v2c"
                config_details="com2sec 설정 발견 (SNMP v1/v2c 사용)"
            fi

            # SNMP v3 사용 여부 확인
            if grep -qi "createUser\|rouser\|rwuser" "$snmp_conf" 2>/dev/null; then
                # v3 사용자 설정이 있으면 v3 사용 중
                if grep -qi "com2sec" "$snmp_conf" 2>/dev/null; then
                    # v1/v2c와 v3가 모두 설정된 경우
                    diagnosis_result="VULNERABLE"
                    status="취약"
                    inspection_summary="SNMP v1/v2c가 활성화됨 (v3와 공존): ${config_details}"
                    local raw_snmp_version=$(grep -E 'com2sec|createUser|rouser' ${snmp_conf} 2>/dev/null)
                    command_result="[Command: grep -E 'com2sec|createUser|rouser' ${snmp_conf}]${newline}${raw_snmp_version}"
                    command_executed="grep -E 'com2sec|createUser|rouser' ${snmp_conf}"
                else
                    # v3만 사용하는 경우
                    diagnosis_result="GOOD"
                    status="양호"
                    inspection_summary="SNMP v3만 사용 중 (보안 설정 적절)"
                    local raw_snmp_v3=$(grep -E 'createUser|rouser|rwuser' ${snmp_conf} 2>/dev/null)
                    command_result="[Command: grep -E 'createUser|rouser|rwuser' ${snmp_conf}]${newline}${raw_snmp_v3}"
                    command_executed="grep -E 'createUser|rouser|rwuser' ${snmp_conf}"
                fi
            elif [ -n "$config_details" ]; then
                # v1/v2c만 사용하는 경우
                diagnosis_result="VULNERABLE"
                status="취약"
                inspection_summary="SNMP v1/v2c 사용 중 (v3 권장): ${config_details}"
                local raw_snmp_v1=$(grep com2sec ${snmp_conf} 2>/dev/null)
                command_result="[Command: grep com2sec ${snmp_conf}]${newline}${raw_snmp_v1}"
                command_executed="grep com2sec ${snmp_conf}"
            else
                # 설정을 찾을 수 없는 경우 (기본 설정일 수 있음)
                diagnosis_result="MANUAL"
                status="수동진단"
                inspection_summary="SNMP 버전 설정을 자동으로 확인할 수 없음 (수동 확인 필요)"
                local raw_snmp_conf=$(cat ${snmp_conf} 2>/dev/null)
                command_result="[Command: cat ${snmp_conf}]${newline}${raw_snmp_conf}"
                command_executed="cat ${snmp_conf}"
            fi
        else
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SNMP 설정 파일을 찾을 수 없음 (수동 확인 필요)"
            local raw_snmp_ls=$(ls /etc/snmp/*.conf 2>&1)
            command_result="[Command: ls /etc/snmp/*.conf 2>/dev/null]${newline}${raw_snmp_ls}"
            command_executed="ls /etc/snmp/*.conf 2>/dev/null"
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
