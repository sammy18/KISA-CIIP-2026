#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-60
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 중
# @Title       : SNMP Community String 복잡성 설정
# @Description : public, private 이외 community 사용
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


ITEM_ID="U-60"
ITEM_NAME="SNMP Community String 복잡성 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="SNMP Community String의복잡성설정을통해비인가자의SNMP정보탈취를방지하기위함"
GUIDELINE_THREAT="SNMP Community String이기본값이거나단순할경우비인가자가SNMP정보를탈취하여시스템정보유출및무단제어가능한위험이존재함"
GUIDELINE_CRITERIA_GOOD="SNMP Community String이복잡하게설정된경우"
GUIDELINE_CRITERIA_BAD=" SNMP Community String이기본값이거나단순하게설정된경우"
GUIDELINE_REMEDIATION="SNMP 설정 파일에서 Community String 복잡하게 변경"

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
    # SNMP Community String 복잡성 확인

    local snmpd_installed=false
    local weak_community=false
    local community_details=""
    local snmp_conf="/etc/snmp/snmpd.conf"

    # 1) SNMP 설치 여부 확인
    if [ -f "$snmp_conf" ] || command -v snmpd >/dev/null 2>&1; then
        snmpd_installed=true
    fi

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        local raw_snmp_check=$(ls ${snmp_conf} 2>&1)
        command_result="[Command: ls ${snmp_conf} 2>/dev/null]${newline}${raw_snmp_check}"
        command_executed="ls ${snmp_conf} 2>/dev/null"
    elif [ ! -f "$snmp_conf" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 설정 파일이 존재하지 않음"
        local raw_snmp_ls=$(ls /etc/snmp/*.conf 2>&1)
        command_result="[Command: ls /etc/snmp/*.conf 2>/dev/null]${newline}${raw_snmp_ls}"
        command_executed="ls /etc/snmp/*.conf 2>/dev/null"
    else
        # 2) Community String 확인 (기본 취약한 community: public, private, cisco 등)
        local default_communities=("public" "private" "cisco" "admin" "monitor" "write" "read" "secret")

        for default_comm in "${default_communities[@]}"; do
            # 대소문자 구분 없이 기본 community string 검색
            if grep -qiE "com2sec.*${default_comm}|rocommunity.*${default_comm}|rwcommunity.*${default_comm}" "$snmp_conf" 2>/dev/null; then
                weak_community=true
                # 해당 라인 추출
                local matching_lines=$(grep -iE "com2sec.*${default_comm}|rocommunity.*${default_comm}|rwcommunity.*${default_comm}" "$snmp_conf" 2>/dev/null | grep -v "^#" | head -3)
                community_details="${community_details}기본 Community '${default_comm}' 사용: ${matching_lines}, "
            fi
        done

        # 3) Community string 복잡성 확인 (길이, 문자열 구성)
        # 사용자 정의 community string 확인
        local custom_communities=$(grep -iE "com2sec|rocommunity|rwcommunity" "$snmp_conf" 2>/dev/null | grep -v "^#" | awk '{for(i=2;i<=NF;i++)print $i}' | head -10)

        if [ -n "$custom_communities" ]; then
            while IFS= read -r comm; do
                if [ -n "$comm" ] && [ ${#comm} -lt 8 ]; then
                    weak_community=true
                    community_details="${community_details}약한 Community '${comm}' (길이 ${#comm}), "
                fi
            done <<< "$custom_communities"
        fi

        if [ "$weak_community" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="약한 SNMP Community String 사용: ${community_details%, }"
            command_result="${community_details%, }"
            command_executed="grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf} | grep -v '^#'"
        else
            diagnosis_result="GOOD"
            status="양호"
            if [ -n "$custom_communities" ]; then
                inspection_summary="SNMP Community String이 안전하게 설정됨 (기본값 미사용, 복잡성 충분)"
                local raw_community=$(grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf} 2>/dev/null | grep -v '^#' | head -5)
                command_result="[Command: grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf} | grep -v '^#']${newline}${raw_community}"
            else
                inspection_summary="SNMP Community String이 설정되지 않았거나 v3만 사용 중"
                local raw_community_check=$(grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf} 2>/dev/null | grep -v '^#' || echo "No community strings or v3 only")
                command_result="[Command: grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf} | grep -v '^#']${newline}${raw_community_check}"
            fi
            command_executed="grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf}"
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
