"""
internal-service : 원래라면 "내부에서만" 접근할 수 있어야 하는 관리자 서비스 역할입니다.

- 컨테이너 내부에서 8001번 포트를 사용합니다.
- 호스트에는 포트를 공개하지 않습니다(브라우저로 직접 접근할 수 없습니다).
- 같은 Docker 네트워크 안에서 http://internal-service:8001/admin 으로 접근할 수 있습니다.

SSRF 실습의 목표는 "사용자가 직접 접근할 수 없는 이 서비스"를
취약한 vulnerable-app 을 통해 대신 호출하게 만드는 것입니다.
"""

import logging

from flask import Flask, jsonify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [internal-service] %(message)s",
)

app = Flask(__name__)


@app.get("/admin")
def admin():
    """
    내부 관리자용으로 가정한 엔드포인트입니다.

    주의: 아래 "SSRF_SUCCESS" 는 실제 비밀번호나 API 키가 아닙니다.
    공격이 성공했는지 학생이 눈으로 확인하기 위한 교육용 표시 문자열일 뿐입니다.
    """
    # 공격이 성공하면 이 로그가 남습니다. (docker compose logs internal-service)
    app.logger.info("[INTERNAL SERVICE] /admin was requested")

    return jsonify(
        {
            "service": "internal-service",
            "message": "This endpoint should not be reachable by users.",
            # 교육용 표시 문자열 (실제 비밀 아님)
            "secret": "SSRF_SUCCESS",
        }
    )


@app.get("/health")
def health():
    """Docker healthcheck 용 엔드포인트입니다. 항상 200을 반환합니다."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # 컨테이너 내부 전용 개발 서버입니다. 호스트에는 포트를 공개하지 않습니다.
    app.run(host="0.0.0.0", port=8001)
