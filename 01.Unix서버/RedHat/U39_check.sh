#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-39
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 불필요한 NFS 서비스 비활성화
# @Description : 시스템 보안 강화를 위해 사용하지 않는 NFS 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-39"
ITEM_NAME="불필요한 NFS 서비스 비활성화"
SEVERITY="(상)"

GUIDELINE_PURPOSE="NFS(Network File System) 서비스는 한 서버의 파일을 많은 서비스 서버들이 공유하여 사용할 때 이용하는서비스지만이를이용한침해사고위험성이높으므로사용하지않는경우중지하기위함"
GUIDELINE_THREAT="NFS 서비스는 서버의 디스크를 클라이언트와 공유하는 서비스로 적정한 보안 설정이 적용되어 있지 않다면불필요한파일공유로인한유출위험이존재함"
GUIDELINE_CRITERIA_GOOD="불필요한NFS서비스관련데몬이비활성화된경우"
GUIDELINE_CRITERIA_BAD="불필요한NFS서비스관련데몬이활성화된경우"
GUIDELINE_REMEDIATION="NFS서비스를사용하지않는경우서비스중지및비활성화설정 ※ 로컬서버에마운트되어있는디렉터리제거및공유디렉터리제거후서비스중지가능"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="NFS 관련 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -E 'nfsd|mountd'"

    # 1. 실제 데이터 추출
    local nfs_procs=$(ps -ef | grep -Ei "nfsd|mountd" | grep -v grep || echo "")

    # 2. 판정 로직
    if [ -n "$nfs_procs" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="불필요한 NFS 서비스가 활성화되어 있습니다."
        command_result="실행 중인 프로세스: [ $(echo $nfs_procs | awk '{print $8}' | xargs) ]"
    else
        command_result="NFS 관련 서비스가 실행 중이지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
