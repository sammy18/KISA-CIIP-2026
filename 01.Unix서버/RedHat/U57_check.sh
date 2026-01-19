#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-57
# @Category    : Unix Server
# @Platform    : RedHat/CentOS/RHEL
# @Severity    : 중
# @Title       : Ftpusers 파일 설정
# @Description : FTP 서비스 root 계정 접근 제한 확인
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


ITEM_ID="U-57"
ITEM_NAME="Ftpusers 파일 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="root계정의FTP직접접속을제한하여root비밀번호정보노출을방지하기위함"
GUIDELINE_THREAT="FTP 서비스에 root 계정으로 접근할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 관리자계정및중요정보를외부로유출할위험이존재함"
GUIDELINE_CRITERIA_GOOD="root계정접속을차단한경우"
GUIDELINE_CRITERIA_BAD="root계정접속을허용한경우"
GUIDELINE_REMEDIATION="Ÿ FTP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ FTP서비스사용시root계정으로직접접속할수없도록설정"

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

    # FTPusers 파일 설정 확인 (root 계정 FTP 접속 제한)
    # 양호: root 계정 접속을 차단한 경우
    # 취약: root 계정 접속을 허용한 경우

    local ftp_installed=false
    local root_blocked=false
    local ftp_config=""

    # 1) FTP 서비스 설치 확인
    local ftp_servers=("vsftpd" "proftpd" "pure-ftpd")
    for svc in "${ftp_servers[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}.service"; then
            ftp_installed=true
            break
        fi
    done

    if [ "$ftp_installed" = false ]; then
        # FTP 서비스가 설치되지 않음
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 서비스 미설치됨"
        local raw_ftp_check=$(systemctl list-unit-files 2>&1 | grep -E 'vsftpd|proftpd|pure-ftpd' || echo "No FTP services found")
        command_result="[Command: systemctl list-unit-files | grep -E 'vsftpd|proftpd|pure-ftpd']${newline}${raw_ftp_check}"
        command_executed="systemctl list-unit-files | grep -E 'vsftpd|proftpd|pure-ftpd'"
    else
        # FTP 서비스가 설치됨 - root 계정 접속 제한 확인

        # 2) /etc/ftpusers 파일 확인 (전통적인 FTP 접속 제한 파일)
        local ftpusers_files=("/etc/ftpusers" "/etc/vsftpd.ftpusers" "/etc/ftpd/ftpusers")
        local ftpusers_found=false

        for ftpusers_file in "${ftpusers_files[@]}"; do
            if [ -f "$ftpusers_file" ]; then
                ftp_config="${ftp_config}${ftpusers_file} 존재${newline}"

                # root 계정이 포함되어 있는지 확인
                if grep -q "^root$" "$ftpusers_file" 2>/dev/null || grep -q "^root[[:space:]]" "$ftpusers_file" 2>/dev/null; then
                    root_blocked=true
                    ftp_config="${ftp_config}  - root 계정 포함됨 (접속 차단)${newline}"
                    ftpusers_found=true
                else
                    ftp_config="${ftp_config}  - root 계정 미포함 (접속 허용됨)${newline}"
                    ftpusers_found=true
                fi
            fi
        done

        # 3) vsftpd 설정 확인
        if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
            local vsftpd_conf="/etc/vsftpd/vsftpd.conf"
            [ ! -f "$vsftpd_conf" ] && vsftpd_conf="/etc/vsftpd.conf"

            # userlist_enable와 userlist_deny 확인
            local userlist_enable=$(grep -E "^[[:space:]]*userlist_enable" "$vsftpd_conf" | grep -v "^[[:space:]]*#" | awk '{print $2}' || echo "")
            local userlist_deny=$(grep -E "^[[:space:]]*userlist_deny" "$vsftpd_conf" | grep -v "^[[:space:]]*#" | awk '{print $2}' || echo "")
            local userlist_file=$(grep -E "^[[:space:]]*userlist_file" "$vsftpd_conf" | grep -v "^[[:space:]]*#" | awk '{print $2}' || echo "")

            ftp_config="${ftp_config}vsftpd 설정:${newline}"
            ftp_config="${ftp_config}  - userlist_enable: ${userlist_enable}${newline}"
            ftp_config="${ftp_config}  - userlist_deny: ${userlist_deny}${newline}"

            if [ -n "$userlist_file" ] && [ -f "$userlist_file" ]; then
                ftp_config="${ftp_config}  - userlist_file: ${userlist_file}${newline}"

                # userlist_file에 root가 포함되어 있는지 확인
                if grep -q "^root$" "$userlist_file" 2>/dev/null || grep -q "^root[[:space:]]" "$userlist_file" 2>/dev/null; then
                    root_blocked=true
                    ftp_config="${ftp_config}  - root 계정 포함됨 (접속 차단)${newline}"
                fi
            fi

            # /etc/vsftpd/user_list 파일 확인 (vsftpd 기본 접속 제한 파일)
            local user_list="/etc/vsftpd/user_list"
            if [ -f "$user_list" ]; then
                if grep -q "^root$" "$user_list" 2>/dev/null || grep -q "^root[[:space:]]" "$user_list" 2>/dev/null; then
                    # userlist_deny=YES 인 경우에만 root 계정 차단
                    if [ "$userlist_deny" = "YES" ] || [ "$userlist_deny" = "yes" ]; then
                        root_blocked=true
                        ftp_config="${ftp_config}  - /etc/vsftpd/user_list에 root 포함 (userlist_deny=YES)${newline}"
                    fi
                fi
            fi
        fi

        # 4) proftpd 설정 확인
        if [ -f /etc/proftpd/proftpd.conf ] || [ -f /etc/proftpd.conf ]; then
            local proftpd_conf="/etc/proftpd/proftpd.conf"
            [ ! -f "$proftpd_conf" ] && proftpd_conf="/etc/proftpd.conf"

            local root_login=$(grep -iE "<Limit LOGIN>" "$proftpd_conf" -A 10 | grep -iE "DenyUser|AllowUser" | grep -i root || echo "")

            if [ -n "$root_login" ]; then
                ftp_config="${ftp_config}proftpd: ${root_login}${newline}"
                if echo "$root_login" | grep -qi "DenyUser.*root"; then
                    root_blocked=true
                    ftp_config="${ftp_config}  - root 계정 차단됨${newline}"
                fi
            fi
        fi

        # 최종 판정
        if [ "$root_blocked" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="root 계정 FTP 접속 차단됨"
            command_result="${ftp_config}"
            command_executed="cat /etc/ftpusers /etc/vsftpd.ftpusers 2>/dev/null; grep -E 'userlist' /etc/vsftpd/vsftpd.conf 2>/dev/null"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="root 계정 FTP 접속 허용됨 (ftpusers 파일에 root 미포함)"
            command_result="${ftp_config}"
            command_executed="cat /etc/ftpusers /etc/vsftpd.ftpusers 2>/dev/null; grep -E 'userlist' /etc/vsftpd/vsftpd.conf 2>/dev/null"
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
