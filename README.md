# KISA 취약점 진단 시스템 (CIIP 2026)

**버전**: 1.0.0
**생성일**: 2026-01-08
**프로젝트**: KISA 주요정보통신기반시설 기술적 취약점 분석·평가

---

## 📋 개요

본 시스템은 KISA(한국인터넷진흥원)의 CIIP(Critical Infrastructure Protection) 가이드라인에 따라 주요정보통신기반시설의 기술적 취약점을 자동 진단하는 오픈소스 도구입니다.

### 지원 플랫폼

| 카테고리 | 플랫폼 | 진단 항목 수 |
|----------|--------|-------------|
| Unix 서버 | Debian, RedHat | U-01 ~ U-67 (67개) |
| Windows 서버 | Windows Server 2019+ | W-01 ~ W-64 (64개) |
| 웹서버 | Apache, Nginx, Tomcat, IIS | WEB-01 ~ WEB-26 (26개) |
| DBMS | MySQL, PostgreSQL, Oracle, MSSQL | D-01 ~ D-26 (26개) |
| PC | Windows PC | P-01 ~ P-18 (18개) |

**총 진단 항목**: 201개

### 주요 기능

✅ **단일 항목 진단**: 개별 취약점 항목 진단
✅ **일괄 진단**: 전체 항목 자동 진단 및 통합 결과 생성
✅ **플랫폼 자동 감지**: OS 및 미들웨어 자동 식별
✅ **멀티 포맷 결과**: JSON + 텍스트 이중 결과 저장
✅ **수동 진단 가이드**: 자동화 불가 항목에 대한 상세 가이드 제공
✅ **보안**: 화이트리스트 기반 명령어 검증, 30초 타임아웃, 3회 재시도 로직

---

## 🚀 빠른 시작

### 1. 사전 요구사항

#### Unix/Linux 환경
```bash
# Bash 4.0+
bash --version

# 필수 도구
command -v jq || echo "jq 필요: apt-get install jq"
command -v curl || echo "curl 필요"
```

#### Windows 환경
```powershell
# PowerShell 5.1+
$PSVersionTable.PSVersion

# Git Bash 또는 WSL 권장
```

### 2. 클론 및 설정

```bash
# 리포지토리 클론
git clone https://github.com/your-org/KISA-CIIP-2026.git
cd KISA-CIIP-2026

# 스크립트 실행 권한 부여 (Unix/Linux)
chmod +x scripts/**/*.sh
chmod +x scripts/lib/*.sh
```

### 3. 진단 실행

#### Unix 서버 (Debian)

```bash
# 단일 항목 진단
cd scripts/01.Unix서버/Debian
./U01_check.sh

# 전체 항목 진단
./01.Unix서버_Debian_run_all.sh
```

#### Windows 서버

```cmd
REM 단일 항목 진단
cd scripts\02.Windows서버
W01_check.bat

REM 전체 항목 진단
02.Windows서버_run_all.bat
```

#### DBMS (MySQL 예시)

```bash
cd scripts/08.DBMS/MySQL

# DBMS 연결 정보 입력 프롬프트 시작
./D01_check.sh

# MySQL 비밀번호 등 입력 후 진단 자동 진행
```

---

## 📁 프로젝트 구조

```
KISA-CIIP-2026/
├── scripts/
│   ├── lib/                          # 핵심 라이브러리
│   │   ├── common.sh                 # 공통 함수
│   │   ├── platform_detector.sh      # 플랫폼 감지
│   │   ├── command_validator.sh      # 명령어 검증
│   │   ├── timeout_handler.sh        # 타임아웃 처리
│   │   ├── result_manager.sh         # 결과 저장
│   │   ├── dbms_connector.sh         # DBMS 연결
│   │   ├── webserver_paths.sh        # 웹서버 경로
│   │   ├── windows_powershell.sh     # PowerShell 래퍼
│   │   └── manual_diagnosis.sh       # 수동 진단 관리
│   │
│   ├── 01.Unix서버/
│   │   ├── Debian/
│   │   │   ├── U01_check.sh ~ U67_check.sh  # 단일 진단 스크립트
│   │   │   └── 01.Unix서버_Debian_run_all.sh
│   │   └── RedHat/
│   │
│   ├── 02.Windows서버/
│   │   ├── W01_check.bat ~ W64_check.bat
│   │   └── 02.Windows서버_run_all.bat
│   │
│   ├── 03.웹서버/
│   │   ├── Apache/   # WEB-01 ~ WEB-26
│   │   ├── Nginx/
│   │   ├── Tomcat/
│   │   └── IIS/
│   │
│   ├── 08.DBMS/
│   │   ├── MySQL/
│   │   ├── PostgreSQL/
│   │   ├── Oracle/
│   │   └── MSSQL/
│   │
│   └── tools/                        # 스크립트 생성 도구
│
├── docs/                             # 문서
│   ├── manual_guides/                # 수동 진단 가이드
│   ├── PLATFORM_SPECIALIZATION_TEST_GUIDE.md
│   └── manual_diagnosis_items.md
│
├── results/                          # 진단 결과 저장소
│   └── YYYYMMDD/
│       ├── hostname_U01_result_YYYYMMDD_HHMMSS.json
│       └── hostname_Unix_Debian_all_results_YYYYMMDD_HHMMSS.txt
│
└── README.md
```

---

## 📊 결과 파일

### JSON 결과 파일

```json
{
  "item_id": "U-01",
  "item_name": "root 계정 원격 접속 제한",
  "status": "양호",
  "diagnosis_result": "GOOD",
  "timestamp": "2026-01-08T10:30:00+09:00",
  "hostname": "server01",
  "inspection_summary": "SSH 설정 확인 완료",
  "command_result": "PermitRootLogin no",
  "guideline": {
    "purpose": "KISA 보안 권고사항 준수",
    "threat": "root 원격 접속 허용 시 시스템 탈취 가능성",
    "criteria": "양호: 원격 접속 제한 / 취약: 원격 접속 허용",
    "remediation": "SSH 설정 파일에서 PermitRootLogin no 설정"
  }
}
```

### 텍스트 결과 파일

```
============================================================
[U-01] root 계정 원격 접속 제한
============================================================
[U-01-START]

SSH 설정 확인 완료

[현황]
1) 진단 확인
command: grep "^PermitRootLogin" /etc/ssh/sshd_config
command_result:
PermitRootLogin no

[U-01-END]

[U-01]Result : GOOD

[참고]
진단 목적: KISA 보안 권고사항 준수
보안 위협: root 원격 접속 허용 시 시스템 탈취 가능성
양호 기준: 원격 접속 제한
취약 기준: 원격 접속 허용
조치 방법: SSH 설정 파일에서 PermitRootLogin no 설정

============================================================
```

---

## 🔒 보안 기능

### 1. 명령어 화이트리스트 (T038-T041)

보안을 위해 모든 명령어가 화이트리스트 검사를 거칩니다.

```bash
# 허용된 명령어 (40+개)
cat, ls, grep, awk, sed, head, tail, find, etc.

# 금지된 패턴 (30+개)
rm -rf, DROP TABLE, shutdown, etc.
```

### 2. DBMS 연결 보안 (T030-T034)

- **3회 재시도**: 연결 실패 시 5초 간격으로 최대 3회 재시도
- **30초 타임아웃**: 응답 없는 연결 자동 종료
- **stdin 입력**: 비밀번호 안전 입력 (`read -s`)
- **SELECT 전용**: DBMS 쿼리는 SELECT만 허용

### 3. 타임아웃 처리 (T035-T037)

```bash
# 30초 타임아웃 설정
timeout 30s diagnose_function

# 타임아웃 발생 시 사용자 선택 프롬프트
# 0: 계속, 1: 건너뛰기, 2: 종료
```

---

## 📖 사용 가이드

### Unix 서버 진단

#### Debian

```bash
cd scripts/01.Unix서버/Debian

# 단일 항목 진단 (예: root 계정 원격 접속)
./U01_check.sh

# 전체 항목 진단 (67개 항목, 약 10-15분 소요)
./01.Unix서버_Debian_run_all.sh

# 결과 확인
ls -l ../results/$(date +%Y%m%d)/
```

#### RedHat

```bash
cd scripts/01.Unix서버/RedHat

# Debian과 동일한 방식으로 진단
./U01_check.sh
./01.Unix서버_RedHat_run_all.sh
```

### Windows 서버 진단

```cmd
REM 명령 프롬프트 또는 PowerShell
cd scripts\02.Windows서버

REM 단일 항목 진단
W01_check.bat

REM 전체 항목 진단 (64개 항목)
02.Windows서버_run_all.bat

REM 결과 확인
dir results\%DATE:~-4%%DATE:~3,2%%DATE:~0,2%\
```

### 웹서버 진단

```bash
# Apache
cd scripts/03.웹서버/Apache
./03.웹서버_Apache_run_all.sh

# Nginx
cd scripts/03.웹서버/Nginx
./03.웹서버_Nginx_run_all.sh
```

### DBMS 진단

```bash
# MySQL 예시
cd scripts/08.DBMS/MySQL

# 진단 시작 (DBMS 연결 정보 입력 프롬프트 표시)
./D01_check.sh

# 입력 예시:
# 호스트네임 [localhost]: 192.168.1.100
# 포트 [3306]: (엔터)
# 사용자명: root
# 비밀번호: ********
# 데이터베이스명 [mysql]: (엔터)
```

---

## 📝 수동 진단 항목

자동화할 수 없는 16개 항목은 수동 진단이 필요합니다.

| 항목 ID | 항목명 | 수동 진단 사유 |
|---------|--------|---------------|
| U-07 | 불필요한 계정 제거 | context_dependent |
| U-12 | 세션 종료시간 설정 | policy_review |
| U-23 | SUID/SGID 파일 점검 | human_judgment |
| WEB-05 | 디렉터리 리스팅 방지 | ui_visual_inspection |
| D-05 | DBA 권한 부여 계정 점검 | context_dependent |

수동 진단 가이드: `docs/manual_guides/`
상세 목록: `docs/manual_diagnosis_items.md`

---

## 🧪 테스트

### 자동화된 테스트 프레임워크

프로젝트는 441개 진단 스크립트에 대한 포괄적인 자동화된 테스트 프레임워크를 제공합니다.

#### 테스트 커버리지

| 플랫폼 | 스크립트 수 | 테스트 완료 | 성공률 | 상태 |
|--------|-----------|------------|--------|------|
| Unix Debian | 67 | ✅ | 85.1% (57/67) | 우수 |
| Unix RedHat | 67 | ✅ | 82.1% (55/67) | 우수 |
| Windows Server | 64 | ✅ | 0% (Server OS 필요) | 예상됨 |
| Web Apache | 26 | ✅ | 46.2% (12/26) | 부분적 |
| Web Nginx | 26 | ✅ | 0% (이미지 최소화) | 제한적 |
| Web Tomcat | 26 | ✅ | 73.1% (19/26) | 양호 |
| Web IIS | 26 | ✅ | 0% (Server+IIS 필요) | 예상됨 |
| DBMS MySQL | 26 | ✅ | 100% (26/26) | 완벽! |
| DBMS PostgreSQL | 26 | ✅ | 100% (26/26) | 완벽! |
| DBMS Oracle | 26 | ⏭️ | 스킵 (이미지 >5GB) | - |
| DBMS MSSQL | 26 | ✅ | 0% (도구 필요) | 제한적 |
| PC | 18 | ✅ | 0% (경로 문제) | 제한적 |
| **전체** | **441** | **359** | **54.3% (195/359)** | **진행 중** |

### 통합 테스트 실행

#### PowerShell 테스트 실행기 (Windows 환경)

```powershell
# Unix Debian 테스트 (67개 스크립트)
powershell -ExecutionPolicy Bypass -File "test\integration\Test-UnixDebianAll.ps1"

# Unix RedHat 테스트 (67개 스크립트)
powershell -ExecutionPolicy Bypass -File "test\integration\Test-UnixRedHatAll.ps1"

# Web Server 테스트
powershell -ExecutionPolicy Bypass -File "test\integration\Test-WebApacheAll.ps1"
powershell -ExecutionPolicy Bypass -File "test\integration\Test-WebTomcatAll.ps1"

# DBMS 테스트 (MySQL - 100% 성공!)
powershell -ExecutionPolicy Bypass -File "test\integration\Test-DBMSMySQLAll.ps1"
powershell -ExecutionPolicy Bypass -File "test\integration\Test-DBMSPostgreSQLAll.ps1"
```

#### 테스트 결과

테스트 결과는 타임스탬프가 있는 디렉토리에 저장됩니다:

```bash
test_results_<timestamp>_debian/
test_results_<timestamp>_mysql/
test_results_<timestamp>_postgresql/
```

각 디렉토리에는 다음이 포함됩니다:
- `test_log.txt` - 사람이 읽을 수 있는 로그
- `test_results.csv` - 기계 읽기 가능한 결과
- `*.error.txt` - 실패한 스크립트의 오류 출력

### 문법 검증

```bash
# Unix 스크립트 문법 검증
find scripts -name "*.sh" -exec shellcheck {} \;

# Windows 스크립트 문법 검증
# PowerShell에서 실행
Get-ChildItem scripts -Recurse -Filter "*.bat" |
    Invoke-ScriptAnalyzer
```

### 테스트 인프라

- **test/lib/OutputParser.ps1** - 진단 출력 파싱
- **test/lib/TimeoutHandler.ps1** - 실행 타임아웃 관리
- **test/lib/ProgressTracker.ps1** - 진행 상황 추적
- **test/lib/IssueReportGenerator.ps1** - 이슈 보고서 생성

자세한 내용: [Comprehensive Test Report](test/results/COMPREHENSIVE_TEST_REPORT_PHASE8.md)

---

## 🏗️ 아키텍처 상세 분석

### 시스템 개요

KISA-CIIP-2026는 **656개 진단 스크립트**와 **10개 핵심 라이브러리**로 구성된 모듈형 취약점 진단 시스템입니다.

```
┌─────────────────────────────────────────────────────────────┐
│                    진단 스크립트 계층                        │
│  (U01_check.sh, WEB01_check.sh, D01_check.sh, etc.)        │
│                         656 files                           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                     핵심 라이브러리 계층                     │
│  ┌──────────────┬──────────────┬──────────────┐            │
│  │ common.sh    │ command_     │ result_      │            │
│  │ (74 lines)   │ validator.sh │ manager.sh   │            │
│  │              │ (329 lines)  │ (634 lines)  │            │
│  ├──────────────┼──────────────┼──────────────┤            │
│  │ platform_    │ timeout_     │ output_mode  │            │
│  │ detector.sh  │ handler.sh   │ .sh          │            │
│  │ (275 lines)  │ (208 lines)  │ (111 lines)  │            │
│  ├──────────────┼──────────────┼──────────────┤            │
│  │ metadata_    │ dbms_        │ json_        │            │
│  │ parser.sh    │ connector.sh │ formatter.sh │            │
│  │ (90 lines)   │ (468 lines)  │ (197 lines)  │            │
│  └──────────────┴──────────────┴──────────────┘            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    OS/플랫폼 추상화 계층                    │
│  Unix/Linux │ Windows │ Web Servers │ DBMS │ PC Clients   │
└─────────────────────────────────────────────────────────────┘
```

---

### 핵심 라이브러리 분석

#### 1. common.sh (74 lines) - 기반 라이브러리

**참조**: 354개 스크립트에서 사용

**주요 함수**:
```bash
# 다중 방식 호스트네임 감지
get_hostname() {
    # 1) hostname 명령어
    # 2) HOSTNAME 환경변수
    # 3) /etc/hostname 파일
    # 4) uname -n 명령어
}

# 결과 파일 경로 생성
create_result_path() {
    # 형식: results/YYYYMMDD/{HOSTNAME}_{ITEM_ID}_result_{TIMESTAMP}
}

# 디스크 공간 확인 (최소 100MB)
check_disk_space() {
    # df 명령어로 available space 확인
    # 100MB 미만 시 critical error
}

# 라이브러리 로드 검증
ensure_libraries_loaded() {
    # runtime에 필수 라이브러리 존재 확인
}
```

**내부 의존성**: `platform_detector.sh`

---

#### 2. platform_detector.sh (275 lines) - 플랫폼 감지

**참조**: common.sh를 통해 간접 참조

**감지 로직**:
```bash
/etc/os-release 파일 분석
    ↓
ID 필드 추출: debian|ubuntu|rhel|centos|almalinux|rocky
    ↓
Fallback:
    - /etc/debian_version → Debian 계열
    - /etc/redhat-release → RedHat 계열
    - 환경변수 (Windows)
```

**주요 함수**:
```bash
detect_platform()              # 메인 디스패처
detect_unix_platform()         # Linux 감지 (/etc/os-release)
detect_windows_platform()      # Windows 감지 (환경변수)
is_debian(), is_redhat()       # 플랫폼 판별 함수
get_platform_package_manager() # apt|yum|dnf|rpm 반환
```

**전문화 함수** (T164-T165):
- `verify_apt_package_manager()` - Debian 패키지 관리자 검증
- `verify_rpm_package_manager()` - RedHat 패키지 관리자 검증

---

#### 3. command_validator.sh (329 lines) - 명령어 보안

**보안 레이어** (T038-T041):

```
┌─────────────────────────────────────────────────────────┐
│ 5단계 명령어 검증 파이프라인                              │
├─────────────────────────────────────────────────────────┤
│ 1) 금지 패턴 매칭 (FORBIDDEN_PATTERNS)                  │
│    - rm -rf, DROP TABLE, shutdown 등 30+ 패턴          │
│                                                         │
│ 2) 화이트리스트 검증 (COMMAND_WHITELIST)                │
│    - cat, ls, grep, awk, sed 등 40+ 안전 명령어        │
│                                                         │
│ 3) 조건부 명령어 검증                                   │
│    - DBMS/PowerShell 쿼리 검증                          │
│                                                         │
│ 4) 플래그 검증                                          │
│    - 위험한 플래그 조합 차단                            │
│                                                         │
│ 5) 런타임 로깅                                         │
│    - command_violations.txt에 기록                     │
└─────────────────────────────────────────────────────────┘
```

**화이트리스트 명령어** (40+개):
```bash
# 파일 연산
cat, ls, find, grep, awk, sed, head, tail, wc, sort, uniq, cut

# 시스템 정보
uname, hostname, date, df, du, ps, uptime, top

# 네트워크
netstat, ss, ip, ifconfig, ping

# 사용자 정보
id, who, w, whoami, groups, last

# 권한 확인
stat, getfacl, namei

# DBMS 클라이언트 (조건부)
mysql, psql, sqlplus, sqlcmd
```

**금지 패턴** (30+개):
```bash
# 파일 파괴
rm -rf, mkfs.*, dd if=, : >

# 권한 변경
chmod 000, chown root.*\*

# 사용자/그룹 삭제
userdel, groupdel

# 프로세스 종료
kill -9, killall, pkill

# 시스템 종료
shutdown, reboot, init 0, halt, poweroff

# DB 파괴
DELETE FROM, DROP TABLE, TRUNCATE TABLE

# 방화벽
iptables.*-F, iptables.*-X
```

**보안 모델**: **Read-Only 강제** - 모든 쓰기 연산 = critical failure

---

#### 4. timeout_handler.sh (208 lines) - 타임아웃 처리

**참조**: 320개 스크립트에서 사용

**타임아웃 상수**:
```bash
DEFAULT_TIMEOUT=30      # 기본 30초
PROMPT_TIMEOUT=60       # 사용자 응답 60초
```

**실행 플로우**:
```
Command 실행
    ↓
Timeout (30s)
    ↓
사용자 프롬프트:
    1) 계속 (2x 타임아웃 연장)
    2) 건너뛰기 (MANUAL 표시)
    3) 종료 (진단 중단)
```

**주요 함수**:
```bash
execute_with_timeout()           # timeout 명령어 래퍼
handle_interactive_timeout()     # 대화형 재시도
prompt_timeout_action()          # 사용자 선택 대화상자
handle_batch_timeout()           # 비대화형 배치 모드
log_timeout_event()              # 타임아웃 감사 로깅
```

---

#### 5. result_manager.sh (634 lines) - 결과 관리

**참조**: 354개 스크립트에서 사용

**경로 생성**:
```bash
# 단일 모드
create_result_file_path()
    → {HOSTNAME}_{ITEM_ID}_result_{YYYYMMDD}_{HHMMSS}.{json|txt}

# Run-all 모드
init_runall_text_file()
    → {HOSTNAME}_{CATEGORY}_{PLATFORM}_all_results_{TIMESTAMP}.txt
```

**JSON 구조**:
```json
{
  "item_id": "U-01",
  "item_name": "root 계정 원격 접속 제한",
  "inspection": {
    "summary": "SSH 설정 확인 완료",
    "status": "양호|취약|수동진단|N/A"
  },
  "final_result": "GOOD|VULNERABLE|MANUAL|N/A",
  "command": "executed_command",
  "command_result": "output_with_escaping",
  "guideline": {
    "purpose": "KISA 보안 권고사항 준수",
    "security_threat": "root 원격 접속 허용 시 탈취 가능성",
    "judgment_criteria_good": "PermitRootLogin no",
    "judgment_criteria_bad": "PermitRootLogin yes",
    "remediation": "SSH 설정 파일에서 PermitRootLogin no 설정"
  },
  "timestamp": "2026-01-19T14:30:20+09:00",
  "hostname": "server01"
}
```

**이스케이프 처리**:
```bash
escape_json_string() {
    # 백슬래시 → \\
    # 큰따옴표 → \"
    # TAB → \t
    # 개행 → \n
}
```

**Run-all 모드** (T025-T029):
```bash
# 환경변수 감지
is_runall_mode() {
    # UNIX_RUNALL_MODE (권장)
    # WS_RUNALL_MODE, PC_RUNALL_MODE, DBMS_RUNALL_MODE
}

# 통계 생성
create_runall_aggregated_results() {
    # 총 항목, 양호, 취약, N/A, 수동, 양호율 계산
}
```

---

#### 6. dbms_connector.sh (468 lines) - DBMS 연결

**보안 기능** (T030-T034):
```bash
# 자격증명 안전 입력
prompt_dbms_connection() {
    # Host [localhost]
    # Port [3306/5432/1521/1433]
    # Username
    # Password (stdin silent 입력, read -s)
    # Database name (MySQL/PostgreSQL/MSSQL)
    # SID (Oracle)
}

# 3회 재시도 로직
for retry in {1..3}; do
    attempt_connection
    if success; break
    sleep 5
done

# 30초 연결 타임아웃
# 비밀번호 메모리 전용 저장 (파일 미기록)
```

**DBMS별 진단 함수**:
```bash
diagnose_mysql()        # T174 - MySQL 보안 검사
diagnose_postgresql()   # T175 - PostgreSQL 보안 검사
diagnose_oracle()       # T176 - Oracle 보안 검사
diagnose_mssql()        # T177 - MSSQL 보안 검사
```

**쿼리 실행**:
```bash
execute_dbms_query() {
    # Read-only 전용: SELECT, SHOW, DESCRIBE, EXPLAIN
    # 타임아웃 래핑
    # 결과 이스케이프 처리
}
```

---

#### 7. output_mode.sh (111 lines) - 출력 모드 관리

**모드**:
```bash
dual  # JSON + TXT 동시 생성 (기본값)
json  # JSON만 생성
text  # TXT만 생성
```

**함수**:
```bash
set_output_mode()      # 모드 설정
output_dual()          # 이중 출력
output_json()          # JSON만
output_text()          # TXT만
create_output()        # 모드 분기
show_progress()        # CLI 진행률 표시
show_diagnosis_start() # 시작 배너
show_diagnosis_complete() # 완료 배너
```

---

### 진단 스크립트 표준 구조

모든 진단 스크립트는 **Template Method 패턴**을 따릅니다:

```bash
#!/bin/bash
# ===========================================================================
# KISA CIIP 2026 진단 스크립트
# ===========================================================================
# @ID         : U-01
# @Category   : Unix 서버
# @Platform   : Debian
# @Severity   : 상
# @Title      : root 계정 원격 접속 제한
# @Description: PermitRootLogin no 설정 확인
# @Guideline  : KISA 2026 가이드라인 준수
# ===========================================================================

# ---------------------------------------------------------------------------
# 라이브러리 로드 (6개 핵심 라이브러리)
# ---------------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/../../../lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../../../lib/command_validator.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../../../lib/timeout_handler.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../../../lib/result_manager.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../../../lib/output_mode.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../../../lib/metadata_parser.sh"

# ---------------------------------------------------------------------------
# 메타데이터 변수 정의
# ---------------------------------------------------------------------------
ITEM_ID="U-01"
ITEM_NAME="root 계정 원격 접속 제한"
GUIDELINE_PURPOSE="KISA 보안 권고사항 준수"
GUIDELINE_THREAT="root 원격 접속 허용 시 시스템 탈취 가능성"
GUIDELINE_CRITERIA_GOOD="PermitRootLogin no 설정"
GUIDELINE_CRITERIA_BAD="PermitRootLogin yes 설정"
GUIDELINE_REMEDIATION="SSH 설정 파일에서 PermitRootLogin no 설정"

# ---------------------------------------------------------------------------
# 진단 함수 (Template Method)
# ---------------------------------------------------------------------------
diagnose() {
    # 1. 서비스 상태 감지 (systemctl → service → ps fallback)
    # 2. 설정 파일 분석 (/etc/ssh/sshd_config)
    # 3. 판정 (GOOD/VULNERABLE/MANUAL/N/A)
    # 4. 결과 저장
}

# ---------------------------------------------------------------------------
# 메인 함수
# ---------------------------------------------------------------------------
main() {
    show_diagnosis_start "$ITEM_ID" "$ITEM_NAME"
    check_disk_space || exit 1
    diagnose
    show_diagnosis_complete "$ITEM_ID" "$ITEM_NAME"
}

# ---------------------------------------------------------------------------
# 직접 실행 가드
# ---------------------------------------------------------------------------
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
```

**U01_check.sh 예시** (374 lines):

```bash
diagnose() {
    # SSH 서비스 감지 (3단계 fallback)
    if systemctl is-active ssh >/dev/null 2>&1; then
        ssh_service_active=true
    elif service ssh status >/dev/null 2>&1; then
        ssh_service_active=true
    elif ps aux | grep -q sshd; then
        ssh_service_active=true
    fi

    # SSH 설정 분석
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        ssh_secure=true
    elif grep -q "^PermitRootLogin prohibit-password" /etc/ssh/sshd_config; then
        ssh_secure=true
    elif grep -q "^PermitRootLogin without-password" /etc/ssh/sshd_config; then
        ssh_secure=true
    fi

    # Telnet 설정 분석
    if [ -f /etc/securetty ] && grep -q "pts" /etc/securetty; then
        telnet_vulnerable=true
    fi

    # 최종 판정
    if [ "$ssh_service_active" = false ] && [ "$telnet_service_active" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSH 및 Telnet 서비스 비활성화"
    elif [ "$ssh_secure" = true ] && [ "$telnet_vulnerable" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSH 설정 안전 (PermitRootLogin no)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="root 원격 접속 가능"
    fi

    # 결과 저장
    save_dual_result "$ITEM_ID" "$ITEM_NAME" "$status" \
        "$diagnosis_result" "$inspection_summary" \
        "$command" "$command_result"
}
```

---

### 디자인 패턴 분석

#### 1. Template Method 패턴
```bash
# 모든 진단 스크립트가 동일한 구조 따름
# diagnose() → Template Method (하위 구현)
# main() → Orchestration (공통)
```

#### 2. Strategy 패턴 (플랫폼 감지)
```bash
# platform_detector.sh가 다양한 플랫폼 감지 전략 제공
detect_platform() {
    case $detected_os in
        debian)    debian_strategy ;;
        redhat)    redhat_strategy ;;
        windows)   windows_strategy ;;
    esac
}
```

#### 3. Security Layer 패턴 (명령어 검증)
```bash
# 5단계 보안 레이어
Layer 1: Forbidden pattern matching (denylist)
Layer 2: Whitelist verification
Layer 3: Conditional command validation (DBMS)
Layer 4: Flag validation
Layer 5: Runtime logging
```

#### 4. Factory 패턴 (결과 생성)
```bash
# 경로 팩토리
create_result_file_path() → Path

# 이중 출력 팩토리
save_dual_result() → JSON + TXT

# JSON 콘텐츠 팩토리
generate_json_content() → JSON Object
```

#### 5. Observer 패턴 (Run-all 모드)
```bash
# 환경변수 관찰
export UNIX_RUNALL_MODE=1

# 스크립트가 모드에 따라 동작 변경
if is_runall_mode; then
    # JSON → stdout (부모 스크립트가 캡처)
    # TXT → 집계 파일에 추가
else
    # 개별 파일 생성
fi
```

#### 6. Retry 패턴 (DBMS 연결)
```bash
for retry in {1..3}; do
    attempt_connection
    if success; then
        break
    fi
    sleep 5
done
```

#### 7. Escaping 패턴 (JSON 안전성)
```bash
# 백슬래시, 큰따옴표, TAB, 개행 이스케이프
escape_json_string() {
    # while loop + sed for multi-line command_result
}
```

---

### 라이브러리 의존성 그래프

```
┌─────────────────────────────────────────────────────────┐
│       개별 진단 스크립트 (354개)                         │
│   U01_check.sh, WEB01_check.sh, D01_check.sh, etc.     │
└─────────────────────────────────────────────────────────┘
                          │
                          ├─→ common.sh
                          │   └─→ platform_detector.sh (internal)
                          │
                          ├─→ command_validator.sh
                          │
                          ├─→ timeout_handler.sh
                          │
                          ├─→ result_manager.sh
                          │
                          ├─→ output_mode.sh
                          │
                          └─→ metadata_parser.sh
                              └─→ json_formatter.sh (internal)

DBMS 스크립트 전용:
    └─→ dbms_connector.sh
    └─→ db_connection_helpers.sh

PowerShell 스크립트:
    └─→ result_manager.ps1
    └─→ output_format.ps1
```

**사용 매트릭스**:

| 라이브러리 | Unix | Web | DBMS | 전체 참조 |
|-----------|------|-----|------|-----------|
| common.sh | ✓ | ✓ | ✓ | 354 |
| result_manager.sh | ✓ | ✓ | ✓ | 354 |
| output_mode.sh | ✓ | ✓ | ✓ | 353 |
| command_validator.sh | ✓ | ✓ | ✓ | 321 |
| timeout_handler.sh | ✓ | ✓ | ✓ | 320 |
| metadata_parser.sh | ✓ | ✓ | ✓ | 134 |
| dbms_connector.sh | - | - | ✓ | 6 |

---

### 플랫폼 전문화

#### Unix/Linux (5 변종)
```bash
# 자동 감지
/etc/os-release → ID 필드

# 패키지 관리자 추상화
get_platform_package_manager()
    → Debian: apt
    → RedHat: yum/dnf/rpm

# 서비스 관리자 추상화
systemctl → service → ps (3단계 fallback)
```

**지원 플랫폼**:
- Debian (67개 항목)
- RedHat (67개 항목)
- AIX (67개 항목)
- HP-UX (67개 항목)
- Solaris (67개 항목)

#### Windows
```powershell
# PowerShell 기반
# 환경변수로 Windows 감지

# 라이브러리
result_manager.ps1 (638 lines)
output_format.ps1 (184 lines)
```

#### 웹서버 (4 플랫폼)
```bash
# 각 웹서버별 특화 경로/설정
Apache:  /etc/apache2/, /etc/httpd/
Nginx:   /etc/nginx/
Tomcat:  $CATALINA_BASE/conf/
IIS:     C:\inetpub\ (PowerShell)
```

**플랫폼별 N/A 처리 예** (Apache WEB01):
```bash
# Apache는 기본 admin 계정 개념 없음
diagnosis_result="N/A"
inspection_summary="이 항목은 Tomcat/IIS/JEUS 대상이며 Apache는 해당하지 않습니다"
```

#### DBMS (4 시스템)
```bash
# 연결 정보 추상화
MySQL:      -h localhost -P 3306 -u root -p
PostgreSQL: -h localhost -p 5432 -U postgres
Oracle:     //localhost:1521/SID
MSSQL:      -S localhost,1433 -U sa

# 버전 인식 쿼리
MySQL:      SELECT VERSION()
PostgreSQL: SELECT version()
Oracle:     SELECT * FROM v$version
MSSQL:      SELECT @@VERSION
```

---

### Run-all 모드 아키텍처

**스크립트**: `01.Unix서버_Debian_run_all.sh` (222 lines)

```bash
# 설정
CATEGORY="Unix 서버"
PLATFORM="Debian"
TOTAL_ITEMS=67
DIAGNOSIS_ITEMS=("U-01" "U-02" ... "U-67")  # 자동 생성
RESULTS_JSON=()  # JSON 출력 수집 배열

# 단일 항목 실행
run_single_check() {
    local item_id="$1"
    export UNIX_RUNALL_MODE=1  # Run-all 모드 활성화

    # 스크립트 실행 및 stdout 캡처 (JSON)
    bash "$script_file" > "$tmp_output" 2>&1

    # JSON 파싱 (awk로 중괄호 매칭)
    json_output=$(awk '/^{/{obj=1; brace++} /^}/{brace--; if(brace==0&&obj)exit} obj{print}')

    # TXT 파일에 추가
    append_runall_text_result "$json_output" "$TXT_FILE"

    # 집계용 배열에 추가
    RESULTS_JSON+=("$json_output")
}

# 메인 실행
main() {
    TXT_FILE=$(init_runall_text_file "${CATEGORY}" "${PLATFORM}" "${SCRIPT_DIR}")

    for item_id in "${DIAGNOSIS_ITEMS[@]}"; do
        run_single_check "$item_id"
    done

    create_runall_aggregated_results "${CATEGORY}" "${PLATFORM}" "${SCRIPT_DIR}" \
        "${TOTAL_ITEMS}" "${RESULTS_JSON[@]}"
}
```

**출력 파일**:
```
{HOSTNAME}_Unix_서버_Debian_all_results_{TIMESTAMP}.json
{HOSTNAME}_Unix_서버_Debian_all_results_{TIMESTAMP}.txt
```

**생성 통계**:
```
총 항목: 67
양호: 45
취약: 12
N/A: 5
수동: 5
양호율: 67.2%
```

---

### 결과 파일 관리

#### 디렉토리 구조
```
results/
└── YYYYMMDD/                                      # 날짜별 폴더
    ├── hostname_U-01_result_20260119_143020.json
    ├── hostname_U-01_result_20260119_143020.txt
    ├── hostname_U-02_result_20260119_143025.json
    ├── hostname_U-02_result_20260119_143025.txt
    ├── hostname_Unix_서버_Debian_all_results_20260119_150000.json
    └── hostname_Unix_서버_Debian_all_results_20260119_150000.txt
```

#### 보존 정책
- **보관 기간**: 90일 (설정 가능)
- **정리 함수**: `cleanup_old_results()` (현재 안전을 위해 비활성화)
- **과거 조회**: `list_historical_results()` (일일 범위 필터)

---

### 보안 아키텍처

#### 1. Read-Only 강제
```bash
# 모든 명령어 화이트리스트 검증
# 쓰기 연산 시도 = critical failure
```

#### 2. Silent Password Input
```bash
# stdin 전용 자격증명 입력
read -s -p "Password: " DB_ADMIN_PASS
```

#### 3. Memory-Only Secrets
```bash
# 비밀번호 절대 파일 미기록
# 사용 후 cleanup_dbms_connection()으로 메모리 정리
unset DB_ADMIN_PASS
```

#### 4. Audit Logging
```bash
# 명령어 위반 로그
log_command_violation()
    → results/YYYYMMDD/command_violations.txt
```

---

### 인코딩 표준

| 플랫폼 | 인코딩 | 줄바꿈 | 검증 |
|--------|--------|--------|------|
| Unix/Linux | UTF-8 (no BOM) | LF | `file -bi script.sh \| grep utf-8` |
| PowerShell | UTF-8 (no BOM) | CRLF | `Test-Path -Path Leaf` |
| Batch | UTF-8 | CRLF | - |

---

### 성능 특성

#### 실행 시간 예시
```bash
# Unix 단일 항목: 2-5초
# Unix 전체 (67개): 10-15분
# DBMS 단일 항목: 3-8초 (연결 포함)
# DBMS 전체 (26개): 5-10분
```

#### 타임아웃 설정
```bash
DEFAULT_TIMEOUT=30s       # 기본 명령어 타임아웃
PROMPT_TIMEOUT=60s        # 사용자 응답 타임아웃
CONNECTION_TIMEOUT=30s    # DBMS 연결 타임아웃
```

---

## 🛠️ 개발

### 스크립트 자동 생성

```bash
# Unix 서버 스크립트 67개 생성
cd scripts/tools
python3 generate_unix_scripts.py

# 전체 플랫폼 스크립트 424개 생성
python3 generate_all_scripts.py
```

### 템플릿 수정

각 진단 스크립트의 `diagnose()` 함수 내 `TODO(human)` 섹션을 수정하여 진단 로직을 구현하세요.

```bash
# 예: U01_check.sh
diagnose() {
    # TODO(human): SSH 설정 확인 로직 구현

    # 진단 로직 작성
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        diagnosis_result="GOOD"
        status="양호"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
    fi
}
```

---

## 🤝 기여

본 프로젝트는 오픈소스입니다. 기여를 환영합니다!

1. Fork 하세요
2. 기능 브랜치 생성 (`git checkout -b feature/AmazingFeature`)
3. 커밋 (`git commit -m 'Add some AmazingFeature'`)
4. 푸시 (`git push origin feature/AmazingFeature`)
5. Pull Request 생성

---

## 📄 라이선스

본 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 LICENSE 파일을 확인하세요.

---

## 📞 지원

- **이슈 트래킹**: [GitHub Issues](https://github.com/your-org/KISA-CIIP-2026/issues)
- **이메일**: uhyang03@gmail.com

---

## 🙏 감사의 말

- KISA(한국인터넷진흥원) CIIP 가이드라인 제공
- 오픈소스 보안 커뮤니티
- 모든 기여자분들

---

**버전**: 1.0.0
**최종 수정**: 2026-01-08
**호환성**: KISA CIIP 2026 가이드라인 준수
