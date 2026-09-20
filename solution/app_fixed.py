"""
solution/app_fixed.py : SSRF 취약점을 수정한 완성본입니다.

사용 방법
---------
막히는 경우에만 참고하세요. 이 파일의 내용을 vulnerable-app/app.py 에 복사한 뒤
`docker compose up --build` 로 다시 빌드하면 수정본으로 실습할 수 있습니다.

핵심 아이디어
-------------
"위험한 것을 골라 막는" 차단 목록(blocklist)이 아니라,
"허용된 것만 통과시키는" 허용 목록(allowlist) 방식으로 검증합니다.
그리고 문자열 검색(`"localhost" in url`)이 아니라
urlparse() 로 URL을 구성요소(스킴/호스트/포트/경로 등)로 나눠서 검사합니다.
"""

import logging
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

# ----------------------------------------------------------------------------
# 허용 목록 (이 실습에서 통과시킬 유일한 요청)
# ----------------------------------------------------------------------------
ALLOWED_SCHEME = "http"
ALLOWED_HOST = "safe-service"
ALLOWED_PORT = 8000
ALLOWED_PATH = "/public"

MAX_URL_LENGTH = 2048            # 지나치게 긴 URL은 파싱 전에 거부합니다.
REQUEST_TIMEOUT_SECONDS = 3      # 응답이 없어도 3초 뒤에는 포기합니다.
MAX_CONTENT_BYTES = 4096         # 응답 본문은 최대 4KB 까지만 돌려줍니다.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [vulnerable-app-fixed] %(message)s",
)

app = Flask(__name__)


def validate_url(url):
    """
    URL이 허용 목록 조건을 모두 만족하는지 검사합니다.

    반환값:
        (True, None)            - 검증 통과
        (False, "이유 문자열")   - 검증 실패

    실패 이유는 학생이 이해할 수 있을 만큼만 알려 주고,
    내부 구조(허용 호스트 이름, 내부 포트 등)는 자세히 노출하지 않습니다.
    """
    # 1) 타입 검사 : 문자열이 아니면 파싱할 수 없습니다.
    if not isinstance(url, str):
        return False, "URL must be a string"

    url = url.strip()
    if not url:
        return False, "URL is required"

    # 2) 길이 제한 : 비정상적으로 긴 입력을 미리 잘라냅니다.
    if len(url) > MAX_URL_LENGTH:
        return False, "URL is too long"

    # 3) 파싱 : 잘못된 형태의 URL은 ValueError 를 던질 수 있습니다.
    #    (예: 대괄호가 깨진 IPv6 주소, 포트 자리에 숫자가 아닌 값)
    try:
        parsed = urlparse(url)
        port = parsed.port          # 포트 형식이 잘못되면 여기서 ValueError
        hostname = parsed.hostname  # 소문자로 정규화된 호스트
    except ValueError:
        return False, "URL could not be parsed"

    # 4) 스킴 검사 : http 만 허용합니다.
    #    file://, gopher://, ftp://, dict:// 같은 스킴은 SSRF 를 더 위험하게 만듭니다.
    if parsed.scheme != ALLOWED_SCHEME:
        return False, "URL scheme is not allowed"

    # 5) 사용자정보(username:password@) 가 있으면 거부합니다.
    #    http://safe-service@internal-service:8001/ 처럼
    #    사람 눈을 속이는 형태를 막기 위해서입니다.
    if parsed.username is not None or parsed.password is not None:
        return False, "URL must not contain user information"

    # 6) 호스트 검사 : 정확히 허용된 호스트만 통과합니다.
    if hostname != ALLOWED_HOST:
        return False, "URL host is not allowed"

    # 7) 포트 검사 : 정확히 허용된 포트만 통과합니다.
    #    포트를 생략한 http://safe-service/public 은 80 포트를 뜻하므로 거부됩니다.
    if port != ALLOWED_PORT:
        return False, "URL port is not allowed"

    # 8) 경로 검사 : 정확히 허용된 경로만 통과합니다.
    if parsed.path != ALLOWED_PATH:
        return False, "URL path is not allowed"

    # 9) query string : 이번 실습에서는 필요하지 않으므로 거부합니다.
    if parsed.query:
        return False, "URL must not contain a query string"

    # 10) fragment(#...) : 서버 요청에는 필요 없으므로 거부합니다.
    if parsed.fragment:
        return False, "URL must not contain a fragment"

    return True, None


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
    """사용자가 입력한 URL을 '검증한 뒤에만' 서버가 대신 요청합니다."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body is required"}), 400

    url = data.get("url")

    # ------------------------------------------------------------------
    # 검증 : 여기를 통과하지 못하면 서버는 아무 요청도 보내지 않습니다.
    # (Sink 인 requests.get() 에 도달하기 전에 막는 것이 핵심입니다.)
    # ------------------------------------------------------------------
    is_valid, reason = validate_url(url)
    if not is_valid:
        app.logger.info("차단된 요청: %s (%s)", url, reason)
        return jsonify({"error": "Blocked by URL policy", "reason": reason}), 400

    url = url.strip()
    app.logger.info("허용된 대상 URL: %s", url)

    try:
        # allow_redirects=False : 대상 서버가 302 로 내부 주소를 가리켜도 따라가지 않습니다.
        # timeout : 응답이 없는 서버 때문에 스레드가 묶이는 것을 막습니다.
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException:
        # 내부 예외나 스택 트레이스는 사용자에게 노출하지 않습니다.
        app.logger.info("요청 실패: %s", url)
        return jsonify({"error": "Request failed"}), 502

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
    app.run(host="0.0.0.0", port=5000)
