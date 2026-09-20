"""
safe-service : 이 실습에서 "정상적으로 요청해도 되는" 외부 리소스 역할을 하는 서비스입니다.

- 컨테이너 내부에서 8000번 포트를 사용합니다.
- 호스트에는 포트를 공개하지 않습니다(docker-compose.yml 에 ports 설정이 없습니다).
- 같은 Docker 네트워크 안에서 http://safe-service:8000/public 으로 접근할 수 있습니다.
"""

import logging

from flask import Flask, jsonify, request

# 로그를 표준 출력으로 내보내면 `docker compose logs safe-service` 로 확인할 수 있습니다.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [safe-service] %(message)s",
)

app = Flask(__name__)


@app.before_request
def log_request_path():
    """어떤 경로로 요청이 들어왔는지 Docker 로그에 남깁니다."""
    app.logger.info("%s %s 요청을 받았습니다.", request.method, request.path)


@app.get("/public")
def public_resource():
    """누구나 요청해도 괜찮은 공개 리소스입니다."""
    return jsonify(
        {
            "service": "safe-service",
            "message": "This is an allowed public resource.",
        }
    )


@app.get("/health")
def health():
    """Docker healthcheck 용 엔드포인트입니다. 항상 200을 반환합니다."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # 컨테이너 내부에서만 사용하는 개발 서버입니다.
    # 호스트로는 포트를 공개하지 않기 때문에 외부에서 직접 접근할 수 없습니다.
    app.run(host="0.0.0.0", port=8000)
