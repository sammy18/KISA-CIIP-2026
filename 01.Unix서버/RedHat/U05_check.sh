#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-05
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : root 이외의 UID가 '0' 금지
# @Description : UID 0인 계정이 root만 있는지 확인
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


ITEM_ID="U-05"
ITEM_NAME="root 이외의 UID가 '0' 금지"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="root 계정과 동일한 UID가 존재하는지 점검하여 root 권한이 일반 사용자 계정이나 비인가자의 접근 위협에안전하게보호되고있는지확인하기위함"
GUIDELINE_THREAT="Ÿ root계정과동일한UID가설정되어있는일반사용자계정도root권한을부여받아관리자가실행할 수있는모든작업이가능한위험이존재함(서비스시작,중지,재부팅,root권한파일편집등) Ÿ root계정과동일한UID를사용하므로사용자감사추적시어려움발생위험이존재함"
GUIDELINE_CRITERIA_GOOD="root계정과동일한UID를갖는계정이존재하지않는경우"
GUIDELINE_CRITERIA_BAD="root계정과동일한UID를갖는계정이존재하는경우"
GUIDELINE_REMEDIATION="Ÿ UID가 0으로 설정된 계정을 0 이외의 중복되지 않은 UID로 변경 또는 불필요한 계정인 경우 제거하도록설정 Ÿ (사용중인계정인경우명령어를통한조치가적용되지않을수있으므로/etc/passwd파일을통해 변경)"

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
    # UID 0인 계정이 root만 있는지 확인

    local uid_zero_accounts=""
    local non_root_uid_zero=false
    local details=""

    # /etc/passwd에서 UID 0인 계정 모두 찾기
    # 실제 awk 명령 실행 결과 캡처
    local uid_zero_accounts=$(awk -F: '$3 == "0" {print $1 ":" $3}' /etc/passwd 2>/dev/null)
    local command_result=""
    local command_executed="awk -F: '\$3 == \"0\" {print \$1 \":\" \$3}' /etc/passwd"

    if [ -z "$uid_zero_accounts" ]; then
        # UID 0 계정을 찾을 수 없음 (비정상)
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/etc/passwd에서 UID 0 계정을 찾을 수 없음. 시스템 상태 확인 필요"
        command_result="${uid_zero_accounts:-[No UID 0 accounts found in /etc/passwd]}"
    else
        # 각 UID 0 계정 확인
        local uid_zero_count=0
        local non_root_list=""

        while IFS= read -r account_info; do
            uid_zero_count=$((uid_zero_count + 1))
            local username=$(echo "$account_info" | cut -d: -f1)
            local uid=$(echo "$account_info" | cut -d: -f2)

            if [ "$username" != "root" ]; then
                non_root_uid_zero=true
                non_root_list="${non_root_list}${username}(UID:${uid}), "
            fi
        done <<< "$uid_zero_accounts"

        # command_result는 원본 awk 출력 저장
        command_result="${uid_zero_accounts}"

        # 최종 판정
        if [ "$non_root_uid_zero" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="root 외 UID 0인 계정 존재: ${non_root_list%, }"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="UID 0인 계정이 root만 존재 (${uid_zero_count}개)"
        fi
    fi

    # 크로스 플랫폼 참고
    # ※ AIX: /etc/passwd, HP-UX: /etc/passwd, Solaris: /etc/passwd (모두 동일)

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
