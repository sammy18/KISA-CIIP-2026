#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-37
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 상
# @Title       : crontab 설정 파일 권한 설정 미흡
# @Description : /etc/crontab 권한 600 확인
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


ITEM_ID="U-37"
ITEM_NAME="crontab 설정 파일 권한 설정 미흡"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="많은 취약점을 가진 echo, discard, daytime, chargen, ntp, snmp 등의 서비스를 중지하여 시스템의보안성을높이기위함"
GUIDELINE_THREAT="해당서비스가활성화된경우,시스템정보유출및DoS공격의대상이될수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="DoS공격에취약한서비스가비활성화된경우"
GUIDELINE_CRITERIA_BAD="DoS공격에취약한서비스가활성화된경우"
GUIDELINE_REMEDIATION="echo, discard, daytime, chargen, ntp, dns,snmp등의서비스비활성화설정"

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

    # crontab 파일 권한 확인
    local crontab_files=(
        "/etc/crontab"
        "/etc/cron.deny"
        "/etc/cron.allow"
        "/etc/at.deny"
        "/etc/at.allow"
    )

    local is_secure=true
    local issues=()
    local file_info=""

    for file in "${crontab_files[@]}"; do
        if [ -f "$file" ]; then
            local perms=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$file" 2>/dev/null || echo "unknown")

            file_info="${file_info}${file}: 권한=${perms}, 소유자=${owner}${newline}"

            # /etc/crontab, cron.deny, at.deny는 600 이하 권장
            if [[ "$file" =~ (crontab|cron.deny|at.deny)$ ]]; then
                if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                    is_secure=false
                    issues+=("${file} 권한=${perms} (600 권장)")
                fi
                # root 소유여부 확인
                if [ "$owner" != "root" ]; then
                    is_secure=false
                    issues+=("${file} 소유자=${owner} (root여야 함)")
                fi
            fi

            # cron.allow, at.allow는 600 권장
            if [[ "$file" =~ (cron.allow|at.allow)$ ]]; then
                if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                    is_secure=false
                    issues+=("${file} 권한=${perms} (600 권장)")
                fi
                if [ "$owner" != "root" ]; then
                    is_secure=false
                    issues+=("${file} 소유자=${owner} (root여야 함)")
                fi
            fi
        fi
    done

    # /etc/cron.d 디렉토리 내 파일 권한 확인
    if [ -d /etc/cron.d ]; then
        file_info="${file_info}${newline}/etc/cron.d 디렉토리 파일:${newline}"
        while IFS= read -r -d '' file; do
            local perms=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$file" 2>/dev/null || echo "unknown")
            file_info="${file_info}  $(basename "$file"): ${perms}, ${owner}${newline}"

            if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                is_secure=false
                issues+=("cron.d/$(basename "$file") 권한=${perms}")
            fi
        done < <(find /etc/cron.d -type f -print0 2>/dev/null)
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="crontab 관련 파일 권한 적절함"
        command_result="${file_info}"
        command_executed="stat -c '%a %U' /etc/crontab /etc/cron.deny /etc/cron.allow /etc/at.deny /etc/at.allow 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="crontab 파일 권한 미흡: ${issues[*]}"
        command_result="${file_info}"
        command_executed="stat -c '%a %U' /etc/crontab /etc/cron.deny /etc/cron.allow 2>/dev/null; find /etc/cron.d -type f -exec stat -c '%n %a %U' {} \\;"
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
