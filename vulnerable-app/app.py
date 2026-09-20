"""
vulnerable-app : 사용자가 입력한 URL을 서버가 대신 요청해서 보여주는 "URL 미리보기" 서비스입니다.

이 파일은 SSRF(Server-Side Request Forgery) 실습을 위해
**의도적으로 취약하게** 만들어져 있습니다. 절대로 실제 서비스에 사용하지 마세요.

실습 흐름
---------
1) 정상 요청 : 사용자 -> vulnerable-app -> safe-service
2) 공격 요청 : 사용자 -> vulnerable-app -> internal-service  (SSRF)

취약점의 핵심
-------------
- Source(오염된 입력) : request.get_json() 으로 받은 사용자 URL
- Sink(위험한 사용처)  : requests.get(url)
- 원인 : 사용자가 준 URL을 아무런 검증 없이 서버가 그대로 요청한다.
"""

import logging

import requests
from flask import Flask, jsonify, render_template, request

# ----------------------------------------------------------------------------
# 실습 안정성을 위한 설정값
# (SSRF 취약점을 고치는 값이 아니라, 실습이 멈추지 않게 하는 안전장치입니다.)
# ----------------------------------------------------------------------------
REQUEST_TIMEOUT_SECONDS = 3      # 대상 서버가 응답하지 않아도 3초 뒤에는 포기합니다.
MAX_CONTENT_BYTES = 4096         # 응답 본문은 최대 4KB 까지만 화면에 돌려줍니다.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [vulnerable-app] %(message)s",
)

app = Flask(__name__)


@app.get("/")
def index():
    """URL 미리보기 화면(HTML)을 보여줍니다."""
    return render_template("index.html")


@app.get("/health")
def health():
    """Docker healthcheck 용 엔드포인트입니다. 항상 200을 반환합니다."""
    return jsonify({"status": "ok"}), 200


@app.post("/preview")
def preview():
    """
    사용자가 입력한 URL을 서버가 대신 요청하고 그 결과를 JSON으로 돌려줍니다.

    요청 형식:
        POST /preview
        Content-Type: application/json
        {"url": "http://safe-service:8000/public"}
    """
    # ------------------------------------------------------------------
    # 1) 입력 확인 (형식 확인일 뿐, 보안 검증이 아닙니다)
    # ------------------------------------------------------------------
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body is required"}), 400

    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    url = url.strip()

    # 접근 로그: 어떤 URL을 요청했는지 남깁니다. (민감 정보는 기록하지 않습니다)
    app.logger.info("요청받은 대상 URL: %s", url)

    # ==================================================================
    # !!! 의도적인 취약점 (SSRF) !!!
    # ------------------------------------------------------------------
    # 아래 requests.get(url) 은 사용자가 보낸 값을 그대로 사용합니다.
    #   - 스킴(http/https/file/gopher ...) 을 확인하지 않습니다.
    #   - 호스트를 확인하지 않습니다.  -> internal-service 도 요청됩니다.
    #   - 포트를 확인하지 않습니다.
    #   - 경로를 확인하지 않습니다.
    # 그래서 브라우저에서 직접 접근할 수 없는 내부 서비스라도
    # "서버가 대신" 요청해 주기 때문에 응답을 훔쳐볼 수 있습니다.
    #
    # 수정 과제:
    #   validate_url(url) 함수를 만들어 허용 목록(allowlist) 방식으로 검증하세요.
    #   막히면 solution/app_fixed.py 를 참고하세요.
    # ==================================================================
    try:
        # allow_redirects=False 는 이번 실습에서 리다이렉트 추적 같은
        # 복잡한 주제를 제외하기 위한 설정입니다.
        # 주의: 이 설정만으로는 SSRF 가 전혀 해결되지 않습니다.
        #       (사용자가 처음부터 내부 주소를 직접 넣으면 그대로 요청됩니다.)
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException:
        # 예외 내용(스택 트레이스)은 사용자에게 보여주지 않습니다.
        app.logger.info("요청 실패: %s", url)
        return jsonify({"error": "Request failed"}), 502

    # 응답 본문은 최대 4KB 까지만 잘라서 문자열로 만듭니다.
    body_text = response.content[:MAX_CONTENT_BYTES].decode("utf-8", errors="replace")

    app.logger.info("대상 서버 응답 상태 코드: %s (%s)", response.status_code, url)

    return jsonify(
        {
            "requested_url": url,
            "status_code": response.status_code,
            "content": body_text,
        }
    )


if __name__ == "__main__":
    # 컨테이너 안에서는 0.0.0.0 으로 바인딩하지만,
    # 호스트로 공개되는 범위는 docker-compose.yml 에서 127.0.0.1 로 제한합니다.
    app.run(host="0.0.0.0", port=5000)
