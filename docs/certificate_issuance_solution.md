# 证书签发方案：FastAPI + cryptography（客户端生成私钥的终极安全版）

## 🎯 目标
为 FISCO BCOS 节点提供一个安全、易用的证书签发服务。**客户端在本地生成并保管私钥**，通过挑战-响应机制证明其对公钥的所有权，服务端验证通过后仅签发证书，实现私钥永不离线。

---

## 🧱 技术选型
- **后端框架**：FastAPI（Python）
- **证书工具**：Python `cryptography`（本地开发 CA，无交互）
- **交互方式**：HTTP API（返回 JSON）
- **安全机制**：**客户端生成私钥** + 挑战-响应（Challenge-Response）

---

## 🛠️ 实现方案（挑战-响应机制）

### 1. FastAPI 接口设计（两步流程）

#### 第一步：请求挑战
```http
POST /request-challenge
```
**请求体（JSON）**：
```json
{
  "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
  "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ..."
}
```
**响应（JSON）**：
```json
{
  "challenge": "随机字符串"
}
```

#### 第二步：签名挑战并请求签发证书
```http
POST /issue-certificate
```
**请求体（JSON）**：
```json
{
  "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
  "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
  "challenge": "随机字符串",
  "signature": "Base64编码的签名"
}
```
**响应（JSON）**：
```json
{
  "node_name": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR2VENDQXFhZ0F3SUJBZ0lKQU5m...",
  "ca_bundle": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR2VENDQXFhZ0F3SUJBZ0lKQU5m..."
}
```

---

### 2. FastAPI 代码实现（基于 cryptography 的本地 CA）

```python
# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import os
import tempfile
import base64
import hashlib
import hmac
import secrets

app = FastAPI()

# 缓存挑战（生产环境建议用 Redis 或数据库）
challenges = {}

class ChallengeRequest(BaseModel):
    original_node_id: str
    public_key: str  # Base64 编码的公钥

class ChallengeResponse(BaseModel):
    challenge: str

class IssueRequest(BaseModel):
    original_node_id: str
    public_key: str
    challenge: str
    signature: str  # Base64 编码的签名

class CertificateResponse(BaseModel):
    node_name: str
    certificate: str   # Base64 编码的 node.crt
    ca_bundle: str     # Base64 编码的 ca.crt

def verify_signature(public_key_b64: str, message: str, signature_b64: str) -> bool:
    # 实现签名验证逻辑（例如使用 cryptography 库）
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature

        public_key = serialization.load_pem_public_key(base64.b64decode(public_key_b64))
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def generate_secure_node_name(original_node_id: str, public_key_b64: str) -> str:
    # 使用公钥和原始节点 ID 生成唯一 node_name
    return hmac.new(
        base64.b64decode(public_key_b64),
        original_node_id.encode(),
        hashlib.sha256
    ).hexdigest()

@app.post("/request-challenge", response_model=ChallengeResponse)
def request_challenge(req: ChallengeRequest):
    challenge = secrets.token_urlsafe(32)
    challenges[challenge] = {"original_node_id": req.original_node_id, "public_key": req.public_key}
    return ChallengeResponse(challenge=challenge)

@app.post("/issue-certificate", response_model=CertificateResponse)
def issue_certificate(req: IssueRequest):
    if req.challenge not in challenges:
        raise HTTPException(status_code=400, detail="无效或过期的挑战")
    
    cached = challenges.pop(req.challenge)
    if cached["original_node_id"] != req.original_node_id or cached["public_key"] != req.public_key:
        raise HTTPException(status_code=400, detail="挑战信息不匹配")

    if not verify_signature(req.public_key, req.challenge, req.signature):
        raise HTTPException(status_code=401, detail="签名验证失败")

    secure_node_name = generate_secure_node_name(req.original_node_id, req.public_key)

    with tempfile.TemporaryDirectory() as tmpdir:
        pub_key_path = os.path.join(tmpdir, "node.pub")
        crt_path = os.path.join(tmpdir, "node.crt")
        ca_path = os.path.join(tmpdir, "ca.crt")

        # 将客户端传来的公钥写入临时文件
        with open(pub_key_path, "wb") as f:
            f.write(base64.b64decode(req.public_key))

        # 使用 cryptography 的本地 CA 签发证书（示意）
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from datetime import datetime, timedelta, timezone

        # 本地生成/加载 CA（生产环境应持久化到安全位置）
        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Fisco Development Root CA"),
        ])
        now = datetime.now(timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        ).sign(ca_key, hashes.SHA256())

        # 从公钥生成证书（示意，实际应从 CSR 读取 subject 与扩展）
        node_public_key = serialization.load_pem_public_key(base64.b64decode(req.public_key))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, secure_node_name)]))
            .issuer_name(ca_cert.subject)
            .public_key(node_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )

        ca_data = base64.b64encode(ca_cert.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
        cert_data = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode("utf-8")

        return CertificateResponse(
            node_name=secure_node_name,
            certificate=cert_data,
            ca_bundle=ca_data
        )
```

---

## ▶️ 部署步骤

### 1. 安装依赖
```bash
pip install fastapi uvicorn cryptography
```

（已移除 Step 依赖，无需初始化 Step CA）

### 3. 启动服务
```bash
uvicorn main:app --reload
```

---

## 🧪 使用方法（客户端示例）

### Python 客户端
```python
import requests
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# 原始节点 ID（由 FISCO BCOS 自动生成）
original_node_id = "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d"

# === 1. 在客户端本地生成并保存私钥 ===
private_key = ec.generate_private_key(ec.SECP256R1())
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("node.key", "wb") as f:
    f.write(private_key_pem)
print("私钥已在本地生成并保存为 node.key")

# === 2. 从私钥派生公钥 ===
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Base64 编码公钥用于API传输
public_key_b64 = base64.b64encode(public_key_pem).decode()

# === 3. 请求挑战 ===
response = requests.post("http://localhost:8000/request-challenge", json={
    "original_node_id": original_node_id,
    "public_key": public_key_b64
})
challenge = response.json()["challenge"]
print(f"获取到挑战: {challenge}")

# === 4. 本地签名挑战 ===
signature = private_key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))
signature_b64 = base64.b64encode(signature).decode()
print("已在本地完成对挑战的签名")

# === 5. 请求签发证书 ===
response = requests.post("http://localhost:8000/issue-certificate", json={
    "original_node_id": original_node_id,
    "public_key": public_key_b64,
    "challenge": challenge,
    "signature": signature_b64
})
data = response.json()
print("成功从服务器获取到签发的证书")

# === 6. 解码并保存证书 ===
with open("node.crt", "wb") as f:
    f.write(base64.b64decode(data["certificate"]))
with open("ca.crt", "wb") as f:
    f.write(base64.b64decode(data["ca_bundle"]))

print("证书 node.crt 和 ca.crt 已保存到本地。")
```

---

## 🔐 安全性说明

- **私钥永不离线**：
  - **私钥在客户端本地生成，从不通过网络传输**。客户端仅通过签名挑战来证明其对公钥的所有权，这是最安全的行业实践。
- **防止重放攻击**：
  - 每个挑战是唯一的，并由服务端控制其生命周期（例如通过缓存过期）。
- **传输安全**：
  - 所有API通信都应强制使用 HTTPS 加密，以保护公钥、证书等信息不被窃听。
- **防滥用**：
  - 可在服务端增加访问频率限制或 API Key 认证，防止恶意消耗签发资源。

---

## ✅ 方案优势

- **终极安全性**：实现了私钥的完全本地化，杜绝了私钥在产生和传输过程中的任何泄露风险。
- **权责清晰**：客户端负责保管最核心的资产（私钥），服务端负责验证和签发，符合最小权限原则。
- **客户端可灵活处理证书存储**：客户端可以决定将证书和私钥存储在任何需要的地方。
- **更符合 RESTful API 设计规范**。

---

## 🧩 进阶建议（可选）

- 添加 Web UI（如 Ant Design + React）供用户触发签发流程。
- 支持批量签发多个节点证书。
- 使用 Redis 或数据库持久化挑战缓存。
- 记录签发日志，便于审计。