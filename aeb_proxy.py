import os
import sys
import time
import json
import socket
import ssl
import logging
import threading
import tempfile
from collections import deque
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import requests
import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from zeroconf import IPVersion, Zeroconf, ServiceInfo

# ---------------------------------------------------------
# 1. 로거 및 기본 설정
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("aeb_proxy")

PORT = int(os.getenv("SERVER_PORT", 8088))
SMARTTHINGS_TOKEN = os.getenv("SMARTTHINGS_TOKEN", "")

# mDNS 인스턴스 전역 변수
zconf: Optional[Zeroconf] = None
service_info_aeb: Optional[ServiceInfo] = None
service_info_eb: Optional[ServiceInfo] = None

# ---------------------------------------------------------
# 2. 로컬 IP 탐색 유틸리티
# ---------------------------------------------------------
def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 실제로 연결을 시도하지 않으며, 로컬 라우팅 테이블을 조회하기 위해 사용합니다.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

SERVER_IP = get_local_ip()
SERVER_START_TIME = int(time.time() * 1000)

# ---------------------------------------------------------
# 3. 데이터스토어 및 모델 정의
# ---------------------------------------------------------
# 인메모리 세션 스토어
sessions: Dict[str, Any] = {}
sessions_lock = threading.Lock()

# 리다이렉트 맵핑 (path -> target_url)
redirects: Dict[str, str] = {}
redirects_lock = threading.Lock()

# 비동기 OAuth 콜백 저장소 (name -> value)
callbacks: Dict[str, str] = {}
callbacks_lock = threading.Lock()

# edgebridge 호환 장치 등록부 (devaddr -> {hubaddr, edgeid})
# registrations.json 파일로 백업하여 상시 구동 신뢰성 제공
REGS_FILE = ".registrations"
registrations: Dict[str, Dict[str, Any]] = {}
registrations_lock = threading.Lock()

def load_registrations():
    global registrations
    if os.path.exists(REGS_FILE):
        try:
            with open(REGS_FILE, "r") as f:
                data = json.load(f)
                # JSON은 키가 문자열이므로 로드 후 메모리 구조에 저장
                registrations = data
                logger.info(f"Loaded {len(registrations)} registrations from {REGS_FILE}")
        except Exception as e:
            logger.error(f"Failed to load registrations: {e}")

def save_registrations():
    try:
        with open(REGS_FILE, "w") as f:
            json.dump(registrations, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save registrations: {e}")

# ---------------------------------------------------------
# 4. Cryptography 기반 RSA / CSR 생성 유틸리티
# ---------------------------------------------------------
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization
except ImportError:
    logger.critical("필수 패키지 'cryptography'가 설치되지 않았습니다. 설치를 진행해 주세요.")
    sys.exit(1)

def generate_rsa_key_and_csr(cn: str) -> tuple[str, str]:
    """RSA 2048 키 쌍과 PKCS#10 CSR(PEM 포맷)을 생성합니다."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # CSR 빌드
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])).sign(private_key, hashes.SHA256())
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    return private_pem, csr_pem

# ---------------------------------------------------------
# 5. Paho-MQTT 클라이언트 및 백그라운드 포워더 클래스
# ---------------------------------------------------------
try:
    import paho.mqtt.client as mqtt
except ImportError:
    logger.critical("필수 패키지 'paho-mqtt'가 설치되지 않았습니다. 설치를 진행해 주세요.")
    sys.exit(1)

class MqttSession:
    def __init__(self, session_id: str, private_key_pem: str, csr_pem: str):
        self.session_id = session_id
        self.private_key_pem = private_key_pem
        self.csr_pem = csr_pem
        
        self.state = "CREATED"
        self.cert_pem: Optional[str] = None
        self.ca_pem: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.port: int = 8883
        self.topics: List[str] = []
        self.qos: int = 1
        self.keep_alive_sec: int = 60
        self.client_id: Optional[str] = None
        
        self.forward_target: Optional[str] = None
        self.messages_buffer = deque(maxlen=200)
        self.seq = 0
        
        self.mqtt_client: Optional[mqtt.Client] = None
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        
        self.last_connected_ts: Optional[int] = None
        self.last_forward_ok_ts: Optional[int] = None
        self.last_error: Optional[str] = None
        
        self.buffer_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.msg_ready_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None

    def start_worker(self):
        self.worker_thread = threading.Thread(target=self._forward_worker_loop, daemon=True)
        self.worker_thread.start()

    def stop(self):
        self.stop_event.set()
        self.msg_ready_event.set()  # 워커 스레드 깨우기
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
            
        if self.mqtt_client:
            try:
                self.mqtt_client.disconnect()
                self.mqtt_client.loop_stop()
            except Exception as e:
                logger.error(f"Error disconnecting MQTT client: {e}")
                
        if self.temp_dir:
            try:
                self.temp_dir.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up temp directory: {e}")

    def _forward_worker_loop(self):
        """백그라운드에서 버퍼링된 메시지를 스마트싱스 허브로 전송하는 루프입니다."""
        while not self.stop_event.is_set():
            # 버퍼에 데이터가 있고 forward_target이 설정될 때까지 대기
            self.msg_ready_event.wait(timeout=1.0)
            if self.stop_event.is_set():
                break
                
            with self.buffer_lock:
                if not self.forward_target or not self.messages_buffer:
                    self.msg_ready_event.clear()
                    continue
                # 가장 오래된 메시지 꺼내오기
                msg_to_send = self.messages_buffer[0]
                target_url = self.forward_target
                
            success = False
            error_details = ""
            backoff = 0.5  # 지수 백오프 시작값: 500ms
            
            # 최대 4회 전송 시도
            for attempt in range(4):
                if self.stop_event.is_set():
                    break
                try:
                    logger.info(f"[{self.session_id}] Forwarding msg seq={msg_to_send['seq']} to {target_url} (attempt {attempt+1})")
                    r = requests.post(
                        target_url,
                        json=msg_to_send,
                        headers={
                            "Content-Type": "application/json",
                            "X-AEB-Api-Version": "1"
                        },
                        timeout=5
                    )
                    if 200 <= r.status_code < 300:
                        success = True
                        break
                    else:
                        error_details = f"Hub returned status code {r.status_code}"
                except Exception as e:
                    error_details = f"Connection failed: {str(e)}"
                    
                time.sleep(backoff)
                backoff *= 2
                
            if success:
                logger.info(f"[{self.session_id}] Successfully forwarded msg seq={msg_to_send['seq']}")
                with self.buffer_lock:
                    if self.messages_buffer and self.messages_buffer[0]["seq"] == msg_to_send["seq"]:
                        self.messages_buffer.popleft()
                    self.last_forward_ok_ts = int(time.time() * 1000)
                    self.last_error = None
            else:
                logger.error(f"[{self.session_id}] Failed to forward msg seq={msg_to_send['seq']}: {error_details}")
                # 4회 모두 실패 시 드롭하고 lastError에 기록 (Spec 명시사항)
                with self.buffer_lock:
                    if self.messages_buffer and self.messages_buffer[0]["seq"] == msg_to_send["seq"]:
                        self.messages_buffer.popleft()
                    self.last_error = f"Failed to forward seq {msg_to_send['seq']}: {error_details}"

# ---------------------------------------------------------
# 6. MQTT 콜백 정의
# ---------------------------------------------------------
def on_connect(client, userdata: MqttSession, flags, rc):
    logger.info(f"[{userdata.session_id}] MQTT OnConnect callback, rc={rc}")
    if rc == 0:
        userdata.state = "CONNECTED"
        userdata.last_connected_ts = int(time.time() * 1000)
        userdata.last_error = None
        # 연결 직후 구독 토픽 등록
        for topic in userdata.topics:
            client.subscribe(topic, qos=userdata.qos)
            logger.info(f"[{userdata.session_id}] Subscribed to topic: {topic}")
    else:
        userdata.state = "ERROR"
        userdata.last_error = f"MQTT connection failed with code {rc}"
        logger.error(f"[{userdata.session_id}] Connect failure: {userdata.last_error}")

def on_disconnect(client, userdata: MqttSession, rc):
    logger.info(f"[{userdata.session_id}] MQTT OnDisconnect callback, rc={rc}")
    if userdata.state != "ERROR":
        userdata.state = "DISCONNECTED"
    if rc != 0:
        userdata.last_error = f"MQTT disconnected unexpectedly (code {rc})"
        logger.warning(f"[{userdata.session_id}] Unexpected disconnect: {userdata.last_error}")

def on_message(client, userdata: MqttSession, msg):
    logger.info(f"[{userdata.session_id}] MQTT Message received on topic '{msg.topic}' (length={len(msg.payload)})")
    
    with userdata.buffer_lock:
        userdata.seq += 1
        seq_num = userdata.seq
        
    try:
        payload_str = msg.payload.decode('utf-8')
        encoding = "utf8"
    except UnicodeDecodeError:
        import base64
        payload_str = base64.b64encode(msg.payload).decode('utf-8')
        encoding = "base64"
        
    msg_obj = {
        "sessionId": userdata.session_id,
        "seq": seq_num,
        "topic": msg.topic,
        "payload": payload_str,
        "payloadEncoding": encoding,
        "ts": int(time.time() * 1000)
    }
    
    with userdata.buffer_lock:
        userdata.messages_buffer.append(msg_obj)
        logger.info(f"[{userdata.session_id}] Message buffered (seq={seq_num}, buffer_len={len(userdata.messages_buffer)})")
        
    userdata.msg_ready_event.set()

# ---------------------------------------------------------
# 7. FastAPI 어플리케이션 및 라우팅 설정
# ---------------------------------------------------------
app = FastAPI(title="Custom AEB Proxy Server", version="1.1.5")

# 공통 에러 응답 유틸리티
def make_error_response(code: str, message: str, status_code: int = 400):
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message
            }
        }
    )

# mDNS 시작/중지 생명주기 제어
@app.on_event("startup")
def startup_event():
    global zconf, service_info_aeb, service_info_eb
    load_registrations()
    
    # mDNS 서비스 등록 브로드캐스트
    try:
        zconf = Zeroconf(ip_version=IPVersion.V4Only)
        desc = {'path': '/'}
        
        service_info_aeb = ServiceInfo(
            "_aeb._tcp.local.",
            f"AEB Proxy Server._aeb._tcp.local.",
            addresses=[socket.inet_aton(SERVER_IP)],
            port=PORT,
            properties=desc,
            server="aeb_proxy.local."
        )
        zconf.register_service(service_info_aeb)
        logger.info(f"mDNS service '_aeb._tcp.local' registered on {SERVER_IP}:{PORT}")

        service_info_eb = ServiceInfo(
            "_edgebridge._tcp.local.",
            f"EdgeBridge Proxy Server._edgebridge._tcp.local.",
            addresses=[socket.inet_aton(SERVER_IP)],
            port=PORT,
            properties=desc,
            server="edgebridge_proxy.local."
        )
        zconf.register_service(service_info_eb)
        logger.info(f"mDNS service '_edgebridge._tcp.local' registered on {SERVER_IP}:{PORT}")
    except Exception as e:
        logger.error(f"Failed to start mDNS broadcaster: {e}")

@app.on_event("shutdown")
def shutdown_event():
    global zconf, service_info_aeb, service_info_eb
    
    # 백그라운드 스레드 및 세션 자원 클린업
    with sessions_lock:
        for session_id, session in list(sessions.items()):
            logger.info(f"Stopping session {session_id} on shutdown")
            session.stop()
        sessions.clear()

    # mDNS 해제
    if zconf:
        try:
            if service_info_aeb:
                zconf.unregister_service(service_info_aeb)
            if service_info_eb:
                zconf.unregister_service(service_info_eb)
            zconf.close()
            logger.info("mDNS services unregistered successfully")
        except Exception as e:
            logger.error(f"Error unregistering mDNS services: {e}")

# ---------------------------------------------------------
# 8. API 엔드포인트 구현
# ---------------------------------------------------------

# 8.1 헬스체크 /api/ping
class PingResponse(BaseModel):
    battery: int
    bridgeDevice: str
    bridgeVersion: str
    serverStartTime: int

@app.get("/api/ping", response_model=PingResponse)
@app.post("/api/ping", response_model=PingResponse)
def api_ping(request: Request):
    # battery: 상시 100% (LXC 컨테이너 환경)
    return PingResponse(
        battery=100,
        bridgeDevice="Custom AEB Linux Proxy",
        bridgeVersion="1.1.5",
        serverStartTime=SERVER_START_TIME
    )

# 8.2 아웃바운드 HTTP 요청 대리전송 /api/forward
@app.api_route("/api/forward", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def api_forward(request: Request, url: str):
    if not url:
        raise HTTPException(status_code=400, detail="Missing url query parameter")
        
    method = request.method
    body_bytes = await request.body()
    
    logger.info(f"Proxying {method} request to {url}")
    
    # 헤더 빌드 및 필터링
    ignored_headers = {"host", "connection", "user-agent", "content-length", "accept-encoding"}
    forward_headers = {}
    for k, v in request.headers.items():
        if k.lower() not in ignored_headers:
            forward_headers[k] = v
            
    forward_headers["User-Agent"] = "SmartThings Edge Hub"
    parsed_url = urlparse(url)
    forward_headers["Host"] = parsed_url.netloc
    
    # SmartThings API 주소 호출 시 인증 토큰 자동 매핑 (Todd Austin / AEB 호환)
    if "api.smartthings.com" in url.lower():
        if "authorization" not in {k.lower() for k in forward_headers.keys()}:
            if SMARTTHINGS_TOKEN:
                token_val = SMARTTHINGS_TOKEN
                if not token_val.startswith("Bearer "):
                    token_val = f"Bearer {token_val}"
                forward_headers["Authorization"] = token_val
                
    try:
        r = requests.request(
            method=method,
            url=url,
            headers=forward_headers,
            data=body_bytes,
            timeout=10
        )
        return Response(
            content=r.content,
            status_code=r.status_code,
            headers={"Content-Type": r.headers.get("Content-Type", "application/octet-stream")}
        )
    except requests.Timeout:
        return Response(content="Gateway Timeout", status_code=504)
    except Exception as e:
        logger.error(f"Outbound forward failed to {url}: {e}")
        return Response(content=f"Bad Gateway: {str(e)}", status_code=502)

# 8.3 MQTT 세션 생성
class CreateSessionReq(BaseModel):
    keyType: str = "RSA2048"
    subjectCN: str = "AWS IoT Certificate"

@app.post("/mqtt/sessions")
def create_mqtt_session(req: Optional[CreateSessionReq] = None):
    subject_cn = req.subjectCN if req else "AWS IoT Certificate"
    
    import secrets
    # 고유한 세션 ID 발급 (예: sess_3c9d2f...)
    session_id = f"sess_{secrets.token_hex(6)}"
    
    logger.info(f"Creating new session {session_id} with CN={subject_cn}")
    
    try:
        private_pem, csr_pem = generate_rsa_key_and_csr(subject_cn)
    except Exception as e:
        logger.error(f"Failed to generate keys/CSR: {e}")
        return make_error_response("KEY_GEN_FAILED", f"Failed to generate RSA keys: {str(e)}")
        
    session = MqttSession(session_id, private_pem, csr_pem)
    session.start_worker()
    
    with sessions_lock:
        sessions[session_id] = session
        
    return {
        "sessionId": session_id,
        "csrPem": csr_pem,
        "state": "CREATED"
    }

# 8.4 MQTT 브로커 mTLS 접속 및 토픽 구독
class ConnectSessionReq(BaseModel):
    certPem: str
    caPem: Optional[str] = None
    endpoint: str
    port: int = 8883
    topics: List[str]
    qos: int = 1
    keepAliveSec: int = 60
    clientId: Optional[str] = None

@app.post("/mqtt/sessions/{session_id}/connect")
def connect_mqtt_session(session_id: str, req: ConnectSessionReq):
    with sessions_lock:
        session: Optional[MqttSession] = sessions.get(session_id)
        
    if not session:
        return make_error_response("SESSION_NOT_FOUND", "Session not found", 404)
        
    logger.info(f"[{session_id}] Request to connect to broker '{req.endpoint}:{req.port}'")
    
    # 기존 클라이언트가 이미 기동 중인 경우 리셋 처리
    if session.mqtt_client:
        try:
            session.mqtt_client.disconnect()
            session.mqtt_client.loop_stop()
        except Exception:
            pass
            
    session.state = "CONNECTING"
    session.cert_pem = req.certPem
    session.ca_pem = req.caPem
    session.endpoint = req.endpoint
    session.port = req.port
    session.topics = req.topics
    session.qos = req.qos
    session.keep_alive_sec = req.keepAliveSec
    session.client_id = req.clientId
    
    # client_id 예외 처리
    effective_client_id = req.clientId if req.clientId else f"aeb-{session_id}"
    
    # 임시 디렉토리 구조에 키와 인증서 파일 임시 기입 (mTLS용)
    if session.temp_dir:
        try:
            session.temp_dir.cleanup()
        except Exception:
            pass
    session.temp_dir = tempfile.TemporaryDirectory()
    
    key_path = os.path.join(session.temp_dir.name, "client.key")
    cert_path = os.path.join(session.temp_dir.name, "client.crt")
    
    try:
        with open(key_path, "w") as f:
            f.write(session.private_key_pem)
        with open(cert_path, "w") as f:
            f.write(req.certPem)
            
        ca_path = None
        if req.caPem:
            ca_path = os.path.join(session.temp_dir.name, "ca.crt")
            with open(ca_path, "w") as f:
                f.write(req.caPem)
        else:
            # 리눅스 시스템 CA 기본 경로 조회 시도
            for path in ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"]:
                if os.path.exists(path):
                    ca_path = path
                    break
                    
        # Paho MQTT 클라이언트 세팅
        client = mqtt.Client(client_id=effective_client_id, clean_session=True, userdata=session)
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_message = on_message
        
        # TLS 환경 세팅
        client.tls_set(
            ca_certs=ca_path,
            certfile=cert_path,
            keyfile=key_path,
            cert_reqs=ssl.CERT_REQUIRED if ca_path else ssl.CERT_NONE,
            tls_version=ssl.PROTOCOL_TLSv1_2
        )
        # SNI(Server Name Indication) 지원 활성화
        client.tls_insecure_set(False)
        
        session.mqtt_client = client
        
        # 백그라운드 연결 시도 및 루프 기동
        client.connect(req.endpoint, req.port, keepalive=req.keepAliveSec)
        client.loop_start()
        
    except Exception as e:
        session.state = "ERROR"
        session.last_error = f"Connect initialization failed: {str(e)}"
        logger.error(f"[{session_id}] Connect initialization error: {e}")
        return make_error_response("CONNECT_FAILED", f"Failed to initialize connection: {str(e)}")
        
    return {
        "sessionId": session_id,
        "state": "CONNECTING",
        "subscribedTopics": req.topics
    }

# 8.5 스마트싱스 허브 대상 전달 목적지 주소(Forward Target) 등록
class ForwardSessionReq(BaseModel):
    hubPort: int
    path: str = "/aeb/ingest"
    hubAddress: Optional[str] = None

@app.put("/mqtt/sessions/{session_id}/forward")
def forward_mqtt_session(session_id: str, req: ForwardSessionReq, request: Request):
    with sessions_lock:
        session: Optional[MqttSession] = sessions.get(session_id)
        
    if not session:
        return make_error_response("SESSION_NOT_FOUND", "Session not found", 404)
        
    # 허브의 IP 추출
    hub_ip = req.hubAddress if req.hubAddress else request.client.host
    target_url = f"http://{hub_ip}:{req.hubPort}{req.path}"
    
    with session.buffer_lock:
        session.forward_target = target_url
        
    logger.info(f"[{session_id}] Registered forward target: {target_url}")
    session.msg_ready_event.set()  # 워커 스레드 깨워 밀린 메시지 송신 시도
    
    return {
        "sessionId": session_id,
        "forwardTarget": target_url
    }

# 8.6 세션 상태 조회
@app.get("/mqtt/sessions/{session_id}/status")
def get_mqtt_session_status(session_id: str):
    with sessions_lock:
        session: Optional[MqttSession] = sessions.get(session_id)
        
    if not session:
        return make_error_response("SESSION_NOT_FOUND", "Session not found", 404)
        
    with session.buffer_lock:
        pending_count = len(session.messages_buffer)
        forward_target = session.forward_target
        
    effective_client_id = session.client_id if session.client_id else f"aeb-{session_id}"
    
    return {
        "sessionId": session_id,
        "state": session.state,
        "subscribedTopics": session.topics,
        "forwardTarget": forward_target,
        "pendingForwardCount": pending_count,
        "lastConnectedTs": session.last_connected_ts,
        "lastForwardOkTs": session.last_forward_ok_ts,
        "lastError": session.last_error,
        "effectiveClientId": effective_client_id,
        "liveClientIdConnections": 1
    }

# 8.7 버퍼링 메시지 직접 수동 폴링 (캐치업 폴링)
@app.get("/mqtt/sessions/{session_id}/messages")
def get_mqtt_session_messages(session_id: str, since: int = 0):
    with sessions_lock:
        session: Optional[MqttSession] = sessions.get(session_id)
        
    if not session:
        return make_error_response("SESSION_NOT_FOUND", "Session not found", 404)
        
    with session.buffer_lock:
        # since 시퀀스보다 높은 메시지만 필터링해서 리스트화
        matched_msgs = [msg for msg in session.messages_buffer if msg["seq"] > since]
        
    return matched_msgs

# 8.8 세션 파기
@app.delete("/mqtt/sessions/{session_id}")
def delete_mqtt_session(session_id: str):
    with sessions_lock:
        session: Optional[MqttSession] = sessions.pop(session_id, None)
        
    if not session:
        return make_error_response("SESSION_NOT_FOUND", "Session not found", 404)
        
    logger.info(f"[{session_id}] Destroying session")
    session.stop()
    
    return Response(status_code=200)

# ---------------------------------------------------------
# 9. 리다이렉트 맵핑 API (AEB 확장 스펙)
# ---------------------------------------------------------
class RedirectCreateReq(BaseModel):
    path: str
    target: str

@app.post("/api/redirect")
def create_redirect(req: RedirectCreateReq):
    path = req.path
    if not path.startswith("/"):
        path = "/" + path
    with redirects_lock:
        redirects[path] = req.target
    logger.info(f"Added redirect: {path} -> {req.target}")
    return {"status": "ok"}

@app.get("/api/redirect")
def list_redirects():
    with redirects_lock:
        return redirects

@app.delete("/api/redirect")
def delete_redirect(path: str):
    if not path.startswith("/"):
        path = "/" + path
    with redirects_lock:
        if path in redirects:
            del redirects[path]
            logger.info(f"Deleted redirect: {path}")
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Redirect not found")

# ---------------------------------------------------------
# 10. OAuth 등을 위한 비동기 콜백 임시 저장소 (AEB 확장 스펙)
# ---------------------------------------------------------
class CallbackCreateReq(BaseModel):
    name: str
    value: str

@app.post("/api/callback")
def create_callback(req: CallbackCreateReq):
    with callbacks_lock:
        callbacks[req.name] = req.value
    logger.info(f"Callback registered: {req.name} = {req.value}")
    return {"status": "ok"}

@app.get("/api/callback")
def list_callbacks():
    with callbacks_lock:
        return callbacks

@app.get("/api/callback/{name}")
def get_callback(name: str):
    with callbacks_lock:
        val = callbacks.get(name)
    if val is not None:
        return {"name": name, "value": val}
    raise HTTPException(status_code=404, detail="Callback not found")

@app.delete("/api/callback/{name}")
def delete_callback(name: str):
    with callbacks_lock:
        if name in callbacks:
            del callbacks[name]
            logger.info(f"Callback deleted: {name}")
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Callback not found")

# ---------------------------------------------------------
# 11. EdgeBridge 호환 로컬 기기 등록 API
# ---------------------------------------------------------
@app.post("/api/register")
def register_device(devaddr: str, hubaddr: str, edgeid: str):
    # 형식: devaddr=192.168.1.10[:port]
    logger.info(f"Registration request: devaddr={devaddr}, hubaddr={hubaddr}, edgeid={edgeid}")
    with registrations_lock:
        registrations[devaddr] = {
            "devaddr": devaddr,
            "hubaddr": hubaddr,
            "edgeid": edgeid
        }
        save_registrations()
    return Response(status_code=200)

@app.delete("/api/register")
def unregister_device(devaddr: str):
    logger.info(f"Unregistration request: devaddr={devaddr}")
    with registrations_lock:
        if devaddr in registrations:
            del registrations[devaddr]
            save_registrations()
            return Response(status_code=200)
    raise HTTPException(status_code=404, detail="Registration not found")

# ---------------------------------------------------------
# 12. 라우팅 미들웨어 및 역방향 프록시 (Inbound Webhook Intercept)
# ---------------------------------------------------------
@app.middleware("http")
async def intercept_registered_requests(request: Request, call_next):
    # 등록된 로컬 기기로부터 유입되는 인바운드 콜백/트리거 패킷 포워딩 (edgebridge 호환)
    client_ip = request.client.host
    client_port = request.client.port
    
    # /api/... 또는 /mqtt/... 등 관리용 API 경로는 인터셉트 예외 처리
    path = request.url.path
    if path.startswith("/api") or path.startswith("/mqtt") or path.startswith("/docs") or path.startswith("/openapi.json"):
        return await call_next(request)
        
    # 리다이렉트 맵핑 우선 검사
    target_redirect = None
    with redirects_lock:
        for prefix, target in redirects.items():
            if path.startswith(prefix):
                target_redirect = (prefix, target)
                break
                
    if target_redirect:
        prefix, target = target_redirect
        sub_path = path[len(prefix):]
        # target_url 구성
        target_url = target.rstrip("/") + "/" + sub_path.lstrip("/")
        logger.info(f"Redirect mapping matched: {path} -> proxying to {target_url}")
        
        # 외부 타깃으로 프록시 수행
        method = request.method
        body_bytes = await request.body()
        forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in {"host", "connection"}}
        try:
            r = requests.request(method=method, url=target_url, headers=forward_headers, data=body_bytes, timeout=10)
            return Response(
                content=r.content,
                status_code=r.status_code,
                headers={"Content-Type": r.headers.get("Content-Type", "application/octet-stream")}
            )
        except Exception as e:
            return Response(content=f"Redirect failed: {str(e)}", status_code=502)

    # 등록된 디바이스 주소 매칭 검증
    # (devaddr가 ip 또는 ip:port 형태이므로 두 가지 경우 모두 검증)
    match_record = None
    with registrations_lock:
        if client_ip in registrations:
            match_record = registrations[client_ip]
        else:
            client_ip_port = f"{client_ip}:{client_port}"
            if client_ip_port in registrations:
                match_record = registrations[client_ip_port]
                
    if match_record:
        # 등록된 기기에서 허브로 전달할 포워딩 경로 구성
        # url 구조: http://<hubaddr>/<devaddr>/<method><path> (Spec 문서 참고)
        hubaddr = match_record["hubaddr"]
        devaddr = match_record["devaddr"]
        method = request.method
        
        target_url = f"http://{hubaddr}/{devaddr}/{method}{path}"
        query_params = request.url.query
        if query_params:
            target_url += f"?{query_params}"
            
        logger.info(f"Intercepted webhook from registered device {devaddr} -> Forwarding to SmartThings hub: {target_url}")
        
        body_bytes = await request.body()
        headers = {
            "Host": hubaddr,
            "Content-Type": request.headers.get("Content-Type", "application/octet-stream")
        }
        
        try:
            # 백그라운드로 전달 시도 (에러 횟수 누적 시 가상 등록 자동 제거)
            # 여기서는 비동기 처리 형태로 빠른 응답 반환을 유도합니다.
            def _async_forward():
                try:
                    res = requests.post(target_url, headers=headers, data=body_bytes, timeout=5)
                    if res.status_code == 200:
                        logger.info(f"Forwarded webhook success for Edge ID {match_record['edgeid']}")
                    else:
                        logger.error(f"Hub returned error {res.status_code} for forward")
                except Exception as ex:
                    logger.error(f"Failed to forward webhook to hub: {ex}")
                    
            threading.Thread(target=_async_forward, daemon=True).start()
            
            # 성공 응답 즉시 리턴
            return Response(status_code=200)
        except Exception as e:
            logger.error(f"Error starting async forward: {e}")
            return Response(status_code=500)

    # 매칭되는 것이 전혀 없으면 404 리턴
    return Response(content="Not Found", status_code=404)

# ---------------------------------------------------------
# 13. 메인 가동부
# ---------------------------------------------------------
if __name__ == "__main__":
    logger.info(f"Starting Custom AEB Proxy Server on {SERVER_IP}:{PORT}...")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
