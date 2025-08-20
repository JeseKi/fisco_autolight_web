"""
证书签发服务的 FastAPI 路由定义。
"""

from fastapi import APIRouter, HTTPException
from . import services
from .schemas import (
    ChallengeRequest,
    ChallengeResponse,
    IssueRequest,
    CertificateResponse,
    VerifyCertificateRequest,
    VerifyCertificateResponse,
)

router = APIRouter(prefix="/ca", tags=["Certificate Authority"])


@router.post("/request-challenge", response_model=ChallengeResponse)
async def request_challenge(req: ChallengeRequest) -> ChallengeResponse:
    """
    客户端请求一个挑战，用于后续证明其对公钥的所有权。
    """
    try:
        return services.request_challenge_service(req)
    except Exception as e:
        # 捕获所有未预期的错误并返回 500
        raise HTTPException(status_code=500, detail=f"内部服务器错误: {str(e)}")


@router.post("/issue-certificate", response_model=CertificateResponse)
async def issue_certificate(req: IssueRequest) -> CertificateResponse:
    """
    客户端提交签名后的挑战，请求签发证书。
    """
    try:
        return services.issue_certificate_service(req)
    except ValueError as e:
        # 捕获业务逻辑中定义的验证错误，返回 400
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        # 捕获核心逻辑中定义的签发错误，返回 500
        raise HTTPException(status_code=500, detail=f"证书签发失败: {str(e)}")
    except Exception as e:
        # 捕获所有未预期的错误并返回 500
        raise HTTPException(status_code=500, detail=f"内部服务器错误: {str(e)}")


@router.post("/verify-certificate", response_model=VerifyCertificateResponse)
async def verify_certificate(req: VerifyCertificateRequest) -> VerifyCertificateResponse:
    """
    客户端上传证书内容，验证该证书是否由我们签发。
    """
    try:
        return services.verify_certificate_service(req)
    except Exception as e:
        # 捕获所有未预期的错误并返回 500
        raise HTTPException(status_code=500, detail=f"内部服务器错误: {str(e)}")