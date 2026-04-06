#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-19
# @Category    : Server
# @Platform    : Tomcat
# @Severity    : 상
# @Title       : 웹서비스SSI(Server Side Includes)사용제한
# @Description : SSI(Server Side Includes) 사용 제한 여부 점검
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

ITEM_ID="WEB-19"
ITEM_NAME="웹서비스SSI(Server Side Includes)사용제한"
SEVERITY="중"

GUIDELINE_PURPOSE="웹서비스내SSI사용을제한하여불법적인데이터접근을차단하여웹서버의보안을강화하기위함"
GUIDELINE_THREAT="Ÿ 웹서비스내SSI사용을제한하지않을경우,공격자가SSI기능을이용하여시스템명령실행및중요 파일탈취등공격이가능하며,이를통해서버시스템침해,데이터유출등이발생할위험이존재함 Ÿ SSI 공격 시 HTML 페이지에 스크립트를 삽입하거나 원격으로 코드를 실행하여 웹 서비스를 악용할 위험이존재함"
GUIDELINE_CRITERIA_GOOD="웹서비스SSI사용설정이비활성화되어있는경우"
GUIDELINE_CRITERIA_BAD="웹서비스SSI사용설정이활성화되어있는경우"
GUIDELINE_REMEDIATION="웹서비스내불필요한SSI사용제한설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_ssi=false

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

    local web_xml_locations=(
        "/etc/tomcat*/web.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/web.xml"
    )

    local ssi_config=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # SSI Servlet 확인 (주석 제외)
                local found_ssi=$(grep -i "SSIServlet|ssi" "${xml_file}" 2>/dev/null | grep -E "servlet|servlet-mapping" | grep -v "^\s*<!--" || true)
                if [ -n "${found_ssi}" ]; then
                    # 활성화된 Servlet인지 확인
                    if ! echo "${found_ssi}" | grep -q "<!--"; then
                        ssi_config="${found_ssi}"
                        has_ssi=true
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="grep -iE 'SSIServlet|ssi' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -3"
    command_result="${ssi_config:-SSI Servlet not found or commented}"

    if [ "${has_ssi}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="SSI Servlet이 활성화되어 있습니다. 코드 삽입 공격 위험으로 비활성화 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSI Servlet이 비활성화되어 있거나 존재하지 않습니다. (보안 권고사항 준수)"
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
