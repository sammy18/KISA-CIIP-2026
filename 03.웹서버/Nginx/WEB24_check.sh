#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-24
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : 웹서비스관리자페이지노출제한
# @Description : 웹 서비스 관리자 페이지 노출 제한 여부 점검
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

ITEM_ID="WEB-24"
ITEM_NAME="웹서비스관리자페이지노출제한"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록 하여 루트디렉터리내악의적인파일업로드및실행을방지하기위함"
GUIDELINE_THREAT="웹서버내별도의파일업로드경로사용및적절한권한설정을하지않을경우,악의적인목적을가진 파일을업로드하여시스템침투,중요정보유출및변조등의침해사고의가능성이있음"
GUIDELINE_CRITERIA_GOOD="별도의업로드경로를사용하고일반사용자의접근권한이부여되지않은경우"
GUIDELINE_CRITERIA_BAD="별도의업로드경로를사용하지않거나,일반사용자의접근권한이부여된경우"
GUIDELINE_REMEDIATION="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local admin_locations_found=0
    local protected_locations=0

    # Process check
    if command -v pgrep >/dev/null; then
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
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
    fi
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi

    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/sites-enabled/*.conf"
    )

    local admin_paths=("admin" "administrator" "wp-admin" "phpmyadmin" "mysql" "management" "console" "dashboard")
    local all_admin_blocks=""
    local all_protected_blocks=""

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                # Check for admin location blocks
                for admin_path in "${admin_paths[@]}"; do
                    local found_admin=$(grep -E "^\s*location\s+[~]?\s*/[^/]*/?${admin_path}" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                    if [ -n "${found_admin}" ]; then
                        all_admin_blocks="${all_admin_blocks}"$'\n'"File: ${conf_file}"$'\n'"${found_admin}"
                        ((admin_locations_found++))

                        # Check if this location has protection (allow/deny or auth_basic)
                        local has_protection=$(grep -A 10 "location.*${admin_path}" "${conf_file}" 2>/dev/null | grep -E "(allow\s+|deny\s+|auth_basic)" | head -1 || true)
                        if [ -n "${has_protection}" ]; then
                            ((protected_locations++))
                            all_protected_blocks="${all_protected_blocks}"$'\n'"File: ${conf_file}"$'\n'"${has_protection}"
                        fi
                    fi
                done
            fi
        done
    done

    command_executed="grep -E '^\\s*location.*/(admin|administrator|wp-admin|phpmyadmin)' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^\\s*#'"
    command_result="${all_admin_blocks:-No admin locations found}"

    if [ ${admin_locations_found} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="관리자 페이지 location 블록이 발견되지 않았습니다. 노출 위험 낮음."
    elif [ ${protected_locations} -eq ${admin_locations_found} ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 관리자 페이지(${admin_locations_found}개)에 접근 제한이 설정되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        local unprotected=$((admin_locations_found - protected_locations))
        inspection_summary="${admin_locations_found}개의 관리자 페이지 location 중 ${unprotected}개에 접근 제한이 없습니다. allow/deny 또는 auth_basic 설정 필요."
    fi

    # Run-all 모드 확인
    # 결과 저장 (run_all 모드는 라이브러리에서 판단)
    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
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
