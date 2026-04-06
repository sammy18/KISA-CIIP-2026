#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-16
# @Category    : Server
# @Platform    : Tomcat
# @Severity    : 상
# @Title       : 웹서비스헤더정보노출제한
# @Description : HTTP 응답 헤더에서 웹서버 버전 정보 등 불필요한 정보 노출 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==========================================================================

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

ITEM_ID="WEB-16"
ITEM_NAME="웹서비스헤더정보노출제한"
SEVERITY="중"

GUIDELINE_PURPOSE="HTTP응답헤더에서웹서버버전및종류,OS정보등웹서버와관련된정보가불필요하게노출되는 것을최소화하기위함"
GUIDELINE_THREAT="웹서버및OS정보가노출될경우공격자에의해해당버전의알려진취약점을이용하여시스템구조와 특성노출및해당취약점을통한공격의위험이존재함"
GUIDELINE_CRITERIA_GOOD="HTTP응답헤더에서웹서버정보가노출되지않는경우"
GUIDELINE_CRITERIA_BAD="HTTP응답헤더에서웹서버정보가노출되는경우"
GUIDELINE_REMEDIATION="응답헤더에표시되는정보를최소한으로제한하여설정"\" 속성 추가 또는 Server 헤더 필터 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local server_hidden=false

    # Process check (Updated for Docker)
    if command -v pgrep >/dev/null; then
        if ! pgrep -f "catalina|tomcat" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Tomcat 웹 서버가 실행 중이 아닙니다."
            command_result="Tomcat process not found"
            command_executed="pgrep -f 'catalina|tomcat'"

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
        fi
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi

    local server_xml_locations=(
        "/etc/tomcat*/server.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/server.xml"
    )

    local connector_config=""

    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # Connector server 속성 확인
                local server_attr=$(grep -E "Connector.*server=" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${server_attr}" ]; then
                    connector_config="${server_attr}"
                    if echo "${server_attr}" | grep -q 'server=""'; then
                        server_hidden=true
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="grep -E 'Connector.*server=' /etc/tomcat*/server.xml 2>/dev/null | grep -v '^\\s*<!--' | head -2"
    command_result="${connector_config:-No server attribute found (default: Apache-Coyote/1.1)}"

    if [ "${server_hidden}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Connector에 server=\"\" 설정이 되어 있습니다. Server 헤더 정보가 숨겨집니다. (보안 권고사항 준수)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Server 헤더에 Tomcat 버전 정보가 노출될 수 있습니다. server=\"\" 설정으로 Server 헤더 숨김 권장."
    fi

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

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if true; then
    main "$@"
fi
