# KISA CIIP 2026 - 진단 스크립트 공개 저장소

**버전**: 2.0.0
**최종 수정**: 2026-04-07
**Repository**: https://github.com/rebugui/KISA-CIIP-2026

---

## 📋 개요

이 저장소는 **KISA(한국인터넷진흥원) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026)** 에 따른 기술적 취약점 진단 스크립트의 공개 버전입니다.


### 지원 플랫폼

| 카테고리 | 플랫폼 | 진단 항목 수 |
|----------|--------|-------------|
| Unix 서버 | Debian, RedHat, AIX, HP-UX, Solaris | U-01 ~ U-67 (67개 × 5 = 335) |
| Windows 서버 | Windows Server 2019+ | W-01 ~ W-64 (64개) |
| 웹서버 | Apache, Nginx, Tomcat (.sh) | WEB-01 ~ WEB-26 (26개 × 3 = 78) |
| 웹서버 | IIS (.ps1) | WEB-01 ~ WEB-26 (26개) |
| DBMS | MySQL, PostgreSQL, Oracle, MSSQL | D-01 ~ D-26 (26개 × 4 = 104) |
| PC | Windows PC | P-01 ~ P-18 (18개) |

**총 진단 항목**: 625개 스크립트

### 주요 기능

- **단일 항목 진단**: 개별 취약점 항목 진단
- **일괄 진단**: 전체 항목 자동 진단 및 통합 결과 생성
- **플랫폼 자동 감지**: OS 및 미들웨어 자동 식별
- **멀티 포맷 결과**: JSON + 텍스트 이중 결과 저장
- **보안**: 화이트리스트 기반 명령어 검증, 30초 타임아웃
- **KISA 가이드라인 내장**: 각 스크립트에 목적, 위협, 판단기준, 조치방법 포함

---

## 🚀 빠른 시작

### 1. 다운로드

```bash
git clone https://github.com/rebugui/KISA-CIIP-2026.git
cd KISA-CIIP-2026
```

### 2. 실행 권한 부여 (Unix/Linux)

```bash
chmod +x lib/*.sh
chmod +x 01.Unix서버/*/*_check.sh
chmod +x 03.웹서버/*/*_check.sh
chmod +x 08.DBMS/*/*_check.sh
```

### 3. 진단 실행

#### Unix 서버 (RedHat 예시)

```bash
cd 01.Unix서버/RedHat

# 단일 항목 진단
./U01_check.sh

# 전체 항목 일괄 진단
./01.Unix서버_RedHat_run_all.sh
```

#### Windows 서버

```powershell
cd 02.Windows서버

# 단일 항목 진단
powershell -ExecutionPolicy Bypass -File .\W01_check.ps1

# 전체 항목 일괄 진단
.\02.Windows서버_run_all.ps1
```

#### 웹서버 (Apache 예시)

```bash
cd 03.웹서버/Apache
./03.웹서버_Apache_run_all.sh
```

#### DBMS (MySQL 예시)

```bash
cd 08.DBMS/mysql

# 진단 시작 (연결 정보 입력 프롬프트)
./D01_check.sh

# 입력 예시:
# 호스트네임 [localhost]: 엔터
# 포트 [3306]: 엔터
# 사용자명: root
# 비밀번호: ********
```

#### PC

```powershell
cd 07.PC

# 단일 항목 진단
powershell -ExecutionPolicy Bypass -File .\P01_check.ps1

# 전체 항목 일괄 진단
.\07.PC_run_all.ps1
```

---

## 📁 디렉토리 구조

```
KISA-CIIP-2026/
├── lib/                          # 공유 라이브러리
│   ├── common.sh                 # 공통 함수 (호스트네임, 경로 생성)
│   ├── result_manager.sh         # 결과 파일 생성, JSON/TXT 출력
│   ├── command_validator.sh      # 명령어 화이트리스트 검증
│   ├── timeout_handler.sh        # 타임아웃 처리, 재시도 로직
│   ├── platform_detector.sh      # 플랫폼 자동 감지
│   ├── dbms_connector.sh         # DBMS 연결, 3회 재시도
│   ├── json_formatter.sh         # JSON 포맷팅
│   ├── output_mode.sh            # dual/json/text 출력 모드
│   ├── result_manager.ps1        # PowerShell 결과 저장
│   ├── output_format.ps1         # PowerShell 출력 모드
│   └── ...
│
├── 01.Unix서버/
│   ├── RedHat/                   # U-01 ~ U-67 (67개)
│   │   ├── U01_check.sh ~ U67_check.sh
│   │   └── 01.Unix서버_RedHat_run_all.sh
│   ├── Debian/                   # U-01 ~ U-67 (67개)
│   ├── AIX/                      # U-01 ~ U-67 (67개)
│   ├── HP-UX/                    # U-01 ~ U-67 (67개)
│   └── Solaris/                  # U-01 ~ U-67 (67개)
│
├── 02.Windows서버/
│   ├── W01_check.ps1 ~ W64_check.ps1
│   └── 02.Windows서버_run_all.ps1
│
├── 03.웹서버/
│   ├── Apache/                   # WEB-01 ~ WEB-26 (.sh)
│   ├── Nginx/                    # WEB-01 ~ WEB-26 (.sh)
│   ├── Tomcat/                   # WEB-01 ~ WEB-26 (.sh)
│   └── IIS/                      # WEB-01 ~ WEB-26 (.ps1)
│
├── 07.PC/
│   ├── P01_check.ps1 ~ P18_check.ps1
│   └── 07.PC_run_all.ps1
│
└── 08.DBMS/
    ├── mysql/                    # D-01 ~ D-26 (.sh)
    ├── postgresql/               # D-01 ~ D-26 (.sh)
    ├── Oracle/                   # D-01 ~ D-26 (.sh)
    └── MSSQL/                    # D-01 ~ D-26 (.sh)
```

---

## 📊 결과 파일

### 저장 위치

```
results/YYYYMMDD/
├── hostname_U01_result_20260407_143020.json
├── hostname_U01_result_20260407_143020.txt
└── hostname_Unix_RedHat_all_results_20260407_150000.json
```

### JSON 결과 예시

```json
{
  "item_id": "U-01",
  "item_name": "root 계정 원격 접속 제한",
  "status": "양호",
  "diagnosis_result": "GOOD",
  "timestamp": "2026-04-07T14:30:20+09:00",
  "hostname": "server01",
  "inspection_summary": "SSH 설정 확인 완료",
  "command_result": "PermitRootLogin no",
  "guideline": {
    "purpose": "KISA 보안 권고사항 준수",
    "threat": "root 원격 접속 허용 시 시스템 탈취 가능성",
    "criteria_good": "PermitRootLogin no 설정",
    "criteria_bad": "PermitRootLogin yes 설정",
    "remediation": "SSH 설정 파일에서 PermitRootLogin no 설정"
  }
}
```

---

## 🔒 보안 기능

### 1. 명령어 화이트리스트

모든 명령어는 화이트리스트 검사를 거칩니다:

**허용 명령어** (40+개):
```bash
cat, ls, grep, awk, sed, head, tail, find, uname, hostname, df, ps, etc.
```

**금지 패턴** (30+개):
```bash
rm -rf, DROP TABLE, shutdown, kill -9, userdel, etc.
```

### 2. DBMS 연결 보안

- **3회 재시도**: 연결 실패 시 5초 간격으로 최대 3회 재시도
- **30초 타임아웃**: 응답 없는 연결 자동 종료
- **stdin 입력**: 비밀번호 안전 입력 (`read -s`)
- **SELECT 전용**: DBMS 쿼리는 SELECT만 허용

### 3. 타임아웃 처리

```bash
DEFAULT_TIMEOUT=30s       # 기본 명령어 타임아웃
PROMPT_TIMEOUT=60s        # 사용자 응답 타임아웃
```

---

## 🛠️ 아키텍처

### 핵심 라이브러리

| 라이브러리 | 기능 | 참조 수 |
|-----------|------|--------|
| common.sh | 기반 함수 (호스트네임, 경로 생성) | 전체 Unix 스크립트 |
| result_manager.sh | 결과 파일 생성, JSON/TXT 출력 | 전체 Unix 스크립트 |
| command_validator.sh | 명령어 화이트리스트 검증 | 전체 Unix 스크립트 |
| timeout_handler.sh | 타임아웃 처리, 재시도 로직 | 전체 Unix 스크립트 |
| output_mode.sh | dual/json/text 모드 | 전체 Unix 스크립트 |
| dbms_connector.sh | DBMS 연결, 3회 재시도 | DBMS 스크립트 |
| platform_detector.sh | 플랫폼 자동 감지 | 전체 Unix 스크립트 |
| result_manager.ps1 | PowerShell 결과 저장 | Windows/PC 스크립트 |

### 진단 스크립트 구조

모든 스크립트는 **Template Method 패턴**을 따릅니다:

```bash
#!/bin/bash
# 메타데이터
ITEM_ID="U-01"
ITEM_NAME="root 계정 원격 접속 제한"

# 라이브러리 로드
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/result_manager.sh"

# KISA 가이드라인 정보
GUIDELINE_PURPOSE="..."
GUIDELINE_THREAT="..."
GUIDELINE_CRITERIA_GOOD="..."
GUIDELINE_CRITERIA_BAD="..."
GUIDELINE_REMEDIATION="..."

# 진단 함수 (Template Method)
diagnose() {
    # 1. 서비스/설정 감지
    # 2. 판정 (GOOD/VULNERABLE/MANUAL/N/A)
    # 3. 결과 저장
}

# 메인 함수
main() {
    show_diagnosis_start "$ITEM_ID" "$ITEM_NAME"
    diagnose
    show_diagnosis_complete "$ITEM_ID" "$ITEM_NAME"
}

main "$@"
```

---

## 📖 사용 가이드

### Unix/Linux 진단

```bash
# RedHat
cd 01.Unix서버/RedHat
./01.Unix서버_RedHat_run_all.sh

# Debian
cd 01.Unix서버/Debian
./01.Unix서버_Debian_run_all.sh

# AIX
cd 01.Unix서버/AIX
./01.Unix서버_AIX_run_all.sh

# HP-UX
cd 01.Unix서버/HP-UX
./01.Unix서버_HP-UX_run_all.sh

# Solaris
cd 01.Unix서버/Solaris
./01.Unix서버_Solaris_run_all.sh
```

### Windows 진단

```powershell
# Windows 서버
cd 02.Windows서버
.\02.Windows서버_run_all.ps1

# Windows PC
cd 07.PC
.\07.PC_run_all.ps1
```

### 웹서버 진단

```bash
# Apache
cd 03.웹서버/Apache
./03.웹서버_Apache_run_all.sh

# Nginx
cd 03.웹서버/Nginx
./03.웹서버_Nginx_run_all.sh

# Tomcat
cd 03.웹서버/Tomcat
./03.웹서버_Tomcat_run_all.sh
```

### IIS 진단 (PowerShell)

```powershell
cd 03.웹서버/IIS
.\03.웹서버_IIS_run_all.ps1
```

### DBMS 진단

```bash
# MySQL
cd 08.DBMS/mysql
./08.DBMS_mysql_run_all.sh

# PostgreSQL
cd 08.DBMS/postgresql
./08.DBMS_postgresql_run_all.sh

# Oracle
cd 08.DBMS/Oracle
./08.DBMS_Oracle_run_all.sh

# MSSQL
cd 08.DBMS/MSSQL
./08.DBMS_MSSQL_run_all.sh
```

---

## 📄 라이선스

GNU Affero General Public License v3.0 (AGPL-3.0)

자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

---

## 🔗 관련 링크

- **공개 Scripts**: https://github.com/rebugui/KISA-CIIP-2026 (이 저장소)
- **KISA 공식 홈페이지**: https://www.kisa.or.kr

---

## 📞 지원

- **이슈 트래킹**: [GitHub Issues](https://github.com/rebugui/KISA-CIIP-2026/issues)
- **이메일**: uhyang03@gmail.com

---

## 🙏 감사의 말

- 오픈소스 보안 커뮤니티
- 모든 기여자분들

---

**버전**: 2.0.0
**최종 수정**: 2026-04-07
**호환성**: KISA CIIP 2026 가이드라인 준수
