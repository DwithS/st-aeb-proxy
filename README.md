# st-aeb-proxy (SmartThings Custom AEB Proxy Server)

스마트싱스(SmartThings) 에어컨 연동을 위해 안드로이드 공단말기(AED/AEB) 대신 상시 전원이 구동되는 **Proxmox LXC 컨테이너(Debian/Ubuntu)** 환경에서 사용할 수 있도록 설계된 가볍고 현대적인 파이썬 기반 프록시/릴레이 서버입니다.

이 서버는 카페용 LG 가전 에어컨 엣지 드라이버 연동에 필수적인 **HTTP Proxy API**와 **MQTT Bridge (mTLS) API** 규격을 완벽하게 충족하며, 백그라운드 구동에 적합하게 격리된 가상환경과 서비스 등록 방식을 제공합니다.

---

## 📂 파일 구조

*   `aeb_proxy.py`: FastAPI와 `paho-mqtt`를 이용해 구현된 코어 프록시 및 MQTT mTLS 브릿지 서버 소스코드
*   `pyproject.toml` 및 `uv.lock`: `uv`에서 프로젝트 명세 및 고정 버전을 관리하기 위해 생성한 현대적인 종속성 정의 파일
*   `edgebridge.service`: 리눅스 부팅 시 백그라운드로 자동 구동하기 위한 `systemd` 서비스 유닛 구성 파일

---

## 🛠️ 요구 사항 및 기술 스택

*   **OS**: Proxmox LXC 컨테이너 (Debian 12 또는 Ubuntu 22.04 LTS 권장)
*   **Python**: Python 3.10 이상
*   **의존성 관리**: `uv` 패키지 매니저
*   **주요 라이브러리**: FastAPI, Uvicorn, Cryptography (RSA/CSR 생성용), Paho-MQTT (mTLS 연결용), Zeroconf (mDNS 브로드캐스트용)

---

## 🚀 빠른 시작 가이드 (LXC 컨테이너 환경)

### 1단계: 프로젝트 파일 복사 및 이동
컨테이너 콘솔에서 소스코드를 모아둘 폴더를 생성하고 해당 디렉토리로 이동한 뒤 파일을 복사합니다.
```bash
sudo mkdir -p /opt/aeb-proxy
cd /opt/aeb-proxy
```

### 2단계: `uv` 패키지 매니저 설치
패키지 설치와 가상환경을 매우 빠르게 수행해 주는 `uv`를 설치합니다.
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# 설치 완료 후 셸을 재부팅하거나 환경 변수를 불러옵니다.
source ~/.bashrc
```

### 3단계: 프로젝트 패키지 설치 및 동기화
`uv`를 이용해 한 번에 가상환경 생성 및 의존성 패키지를 동기화합니다.
```bash
# 가상환경(.venv) 생성 및 동기화 자동 진행
uv sync
```

### 4단계: 동작 검증
서버가 정상적으로 시동되고, RSA 키/CSR이 정상 생성되는지 임시로 작동을 테스트합니다. (로컬 확인용 검증 스크립트 실행)
```bash
# verify.py 스크립트 실행
uv run verify.py
```
> `All verification tests PASSED successfully!` 가 출력되면 정상적으로 키 발급 및 API 준비가 끝난 상태입니다.

---

## ⚙️ systemd를 이용한 상시 백그라운드 서비스 등록

컨테이너가 부팅될 때 자동으로 프록시 서버가 실행되도록 설정합니다.

1. **서비스 파일 복사**:
   ```bash
   sudo cp edgebridge.service /etc/systemd/system/edgebridge.service
   ```
2. **서비스 활성화 및 기동**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable edgebridge.service
   sudo systemctl start edgebridge.service
   ```
3. **상태 및 로그 모니터링**:
   ```bash
   # 서비스 작동 상태 확인
   sudo systemctl status edgebridge.service

   # 실시간 릴레이 중계 로그 및 mDNS 등록 정보 확인
   sudo journalctl -u edgebridge.service -f
   ```

---

## 📡 주요 API 엔드포인트 개요

*   **기본 포트**: `8088` (환경변수 `SERVER_PORT`로 조정 가능)
*   **mDNS 탐색 이름**: `_aeb._tcp.local` (스마트싱스 허브가 자동으로 검색하여 연동할 수 있도록 함)

### HTTP API
*   `GET/POST /api/ping`: 헬스체크 및 서버 상태 확인 (배터리 및 구동 시간 조회)
*   `ALL /api/forward?url=<target>`: 외부 클라우드 API 호출 대행 프록시

### MQTT Bridge API
*   `POST /mqtt/sessions`: 에어컨 전용 MQTT 세션을 생성하고 드라이버 서명에 필요한 2048bit CSR 발급
*   `POST /mqtt/sessions/{id}/connect`: ThinQ AWS IoT MQTT 브로커와 서명된 클라이언트 인증서를 통해 mTLS 연결 개시
*   `PUT /mqtt/sessions/{id}/forward`: MQTT 브로커로부터 푸시되는 상태 메시지를 전달받을 스마트싱스 허브의 인카밍 엔드포인트 주소 등록

---

## ⚖️ 라이선스
본 프로젝트는 **Apache License 2.0**을 따릅니다.
Original edgebridge concept by Todd Austin (`toddaustin07`).
