#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.2
# @Last Updated: 2026-04-23
# ============================================================================
# [점검 항목 상세]
# @ID          : U-42
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : 불필요한 RPC 서비스 비활성화
# @Description : 취약점이 있는 불필요한 RPC 서비스(rusersd, rwalld, rstatd 등) 비활성화 확인
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


ITEM_ID="U-42"
ITEM_NAME="불필요한 RPC 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="많은 취약점(버퍼 오버 플로우, DoS, 원격 실행 등)이 존재하는 RPC 서비스를 비활성화하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="RPC 서비스의 취약점을 통해 비인가자가 root 권한 획득 및 각종 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 RPC 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 RPC 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 RPC 서비스 중지 및 비활성화 설정"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    local is_secure=true
    local active_services=()
    local service_status=""

    # 1) 취약한 RPC 프로세스 확인
    local rpc_procs=$(ps -ef 2>/dev/null | grep -Ei "rusersd|rwalld|rstatd|rpc\.cmsd|rpc\.ttdbserverd|sprayd|walld" | grep -v grep || echo "")
    if [ -n "$rpc_procs" ]; then
        is_secure=false
        local proc_names=$(echo "$rpc_procs" | awk '{print $8}' | sort -u | xargs)
        active_services+=("RPC 프로세스: ${proc_names}")
        service_status="${service_status}취약 RPC 프로세스 실행 중\\n"
    fi

    # 2) AIX inetd.conf에서 RPC 서비스 확인
    if [ -f /etc/inetd.conf ]; then
        for rpc_svc in rusersd rwalld rstatd sprayd; do
            local inetd_entry=$(grep "$rpc_svc" /etc/inetd.conf 2>/dev/null | grep -v "^#" || echo "")
            if [ -n "$inetd_entry" ]; then
                is_secure=false
                active_services+=("${rpc_svc} (inetd enabled)")
                service_status="${service_status}${rpc_svc}: inetd.conf에서 활성화됨\\n"
            fi
        done || true
    fi

    # 3) rpcinfo로 등록된 RPC 서비스 확인
    if command -v rpcinfo >/dev/null 2>&1; then
        local rpc_info=$(rpcinfo -p 2>/dev/null | grep -Ei "rusersd|rwalld|rstatd|sprayd|cmsd|ttdbserverd" || echo "")
        if [ -n "$rpc_info" ]; then
            is_secure=false
            active_services+=("rpcinfo에 취약 RPC 서비스 등록됨")
            service_status="${service_status}rpcinfo: 취약 RPC 서비스 발견\\n"
        fi
    fi

    # 명령어 결과 수집
    local ps_raw=$(ps -ef 2>/dev/null | grep -Ei "rusersd|rwalld|rstatd|rpc\.cmsd|rpc\.ttdbserverd|sprayd" | grep -v grep || echo "No vulnerable RPC processes found")
    local rpcinfo_raw=""
    if command -v rpcinfo >/dev/null 2>&1; then
        rpcinfo_raw=$(rpcinfo -p 2>/dev/null || echo "rpcinfo not available")
    else
        rpcinfo_raw="rpcinfo command not found"
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 RPC 서비스가 비활성화되어 있습니다."
        command_result="[Command: ps -ef | grep rpc]${newline}${ps_raw}${newline}${newline}[Command: rpcinfo -p]${newline}${rpcinfo_raw}"
        command_executed="ps -ef | grep -Ei 'rusersd|rwalld|rstatd'; rpcinfo -p"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="보안에 취약한 RPC 서비스가 활성화되어 있습니다: ${active_services[*]}"
        command_result="[Command: ps -ef | grep rpc]${newline}${ps_raw}${newline}${newline}[Command: rpcinfo -p]${newline}${rpcinfo_raw}"
        command_executed="ps -ef | grep -Ei 'rusersd|rwalld|rstatd'; rpcinfo -p"
    fi

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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    check_disk_space

    diagnose

    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
