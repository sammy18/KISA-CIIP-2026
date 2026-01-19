#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-43
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : NIS, NIS+ 점검
# @Description : NIS 서비스 비활성화, NIS+ 서비스 사용 확인
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


ITEM_ID="U-43"
ITEM_NAME="NIS, NIS+ 점검"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="인증 없는 원격 접속을 방지하여 시스템 보안을 강화하기 위함"
GUIDELINE_THREAT="rsh, rlogin, rexec 등의 r 계열 서비스가 활성화된 경우, 패스워드 없이 원격 접속이 가능하여 공격자가 시스템에 무단 접근하고 악의적인 명령을 실행할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="r 계열 서비스(rsh, rlogin, rexec)가 모두 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="r 계열 서비스 중 하나라도 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="r 계열 서비스 중지 및 패키지 제거, /etc/inetd.conf 및 /etc/xinetd.d 설정 파일에서 해당 서비스 비활성화"

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

    # NIS/NIS+ 서비스 점검
    # 양호: NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우
    # 취약: NIS 서비스가 활성화된 경우

    local nis_running=false
    local nis_plus_used=false
    local nis_info=""
    local active_nis_services=()

    # 1) systemd 서비스 확인 (ypbind, ypserv, yppasswdd - NIS 서비스)
    local nis_services=("ypbind" "ypserv" "yppasswdd" "ypxfrd")
    for svc in "${nis_services[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}.service"; then
            local svc_state=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            local svc_enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")
            nis_info="${nis_info}${svc}: ${svc_state} (${svc_enabled})${newline}"

            if [ "$svc_state" = "active" ]; then
                nis_running=true
                active_nis_services+=("${svc}")
            fi
        fi
    done

    # 2) NIS+ 서비스 확인 (rpc.nisd, nis+ - 안전한 버전)
    local nis_plus_services=("rpc.nisd" "nisplus" "nis+")
    for svc in "${nis_plus_services[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}.service"; then
            local svc_state=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            nis_info="${nis_info}NIS+ ${svc}: ${svc_state}${newline}"

            if [ "$svc_state" = "active" ]; then
                nis_plus_used=true
            fi
        fi
    done

    # 3) RPC 서비스 확인 (NIS는 RPC 기반)
    if command -v rpcinfo &>/dev/null; then
        local ypserv_rpc=$(rpcinfo -p 2>/dev/null | grep "ypserv" || echo "")
        if [ -n "$ypserv_rpc" ]; then
            nis_running=true
            nis_info="${nis_info}RPC ypserv: 활성화됨${newline}${ypserv_rpc}${newline}"
        fi
    fi

    # 4) /etc/yp.conf 확인 (NIS 클라이언트 설정)
    if [ -f /etc/yp.conf ]; then
        local yp_conf=$(grep -v "^[[:space:]]*#" /etc/yp.conf | grep -v "^[[:space:]]*$" || echo "")
        if [ -n "$yp_conf" ]; then
            nis_running=true
            nis_info="${nis_info}/etc/yp.conf: NIS 클라이언트 설정됨${newline}${yp_conf}${newline}"
        fi
    fi

    # 5) /etc/defaultdomain 확인 (NIS 도메인)
    if [ -f /etc/defaultdomain ]; then
        local nis_domain=$(cat /etc/defaultdomain 2>/dev/null || echo "")
        if [ -n "$nis_domain" ]; then
            nis_info="${nis_info}NIS 도메인: ${nis_domain}${newline}"
        fi
    fi

    # domainname 명령어로 NIS 도메인 확인
    if command -v domainname &>/dev/null; then
        local current_domain=$(domainname 2>/dev/null || echo "")
        if [ -n "$current_domain" ] && [ "$current_domain" != "(none)" ]; then
            nis_info="${nis_info}현재 NIS 도메인: ${current_domain}${newline}"
        fi
    fi

    # 6) /var/yp 디렉토리 확인 (NIS 서버)
    if [ -d /var/yp ]; then
        local yp_domains=$(ls /var/yp 2>/dev/null || echo "")
        if [ -n "$yp_domains" ]; then
            nis_running=true
            nis_info="${nis_info}/var/yp: NIS 도메인 존재 (${yp_domains})${newline}"
        fi
    fi

    # 7) portmap/rpcbind 확인 (NIS는 RPC 기반)
    if systemctl is-active rpcbind &>/dev/null || systemctl is-active portmap &>/dev/null; then
        local rpcbind_state=$(systemctl is-active rpcbind 2>/dev/null || systemctl is-active portmap 2>/dev/null || echo "unknown")
        nis_info="${nis_info}rpcbind/portmap: ${rpcbind_state}${newline}"
    fi

    # 최종 판정
    if [ "$nis_running" = false ]; then
        # NIS 서비스가 실행되지 않음 (양호)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NIS 서비스 비활성화됨"
        command_result="${nis_info}"
        command_executed="systemctl is-active ypbind ypserv yppasswdd; ls /var/yp 2>/dev/null; rpcinfo -p 2>/dev/null"
    elif [ "$nis_plus_used" = true ]; then
        # NIS+ 사용 (안전함 - 양호)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NIS+ 서비스 사용 (안전함)"
        command_result="${nis_info}"
        command_executed="systemctl is-active rpc.nisd ypbind ypserv; rpcinfo -p 2>/dev/null"
    else
        # NIS 서비스 활성화됨 (취약)
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NIS 서비스 활성화됨: ${active_nis_services[*]} (NIS+ 사용 권장)"
        command_result="${nis_info}"
        command_executed="systemctl is-active ypbind ypserv yppasswdd; cat /etc/yp.conf 2>/dev/null; rpcinfo -p"
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
