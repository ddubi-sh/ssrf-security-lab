/* ============================================================================
   LinkLens - 화면 동작 스크립트

   이 스크립트는 사용자가 입력한 URL을 같은 출처의 /preview API 로 보내고
   그 결과를 화면에 그리는 일만 합니다.

   - 입력값이 비어 있는지만 확인합니다.
   - 호스트, IP, 포트, 스킴은 검사하거나 차단하지 않습니다. (검증은 서버의 몫입니다.)
   - 브라우저가 대상 주소로 직접 요청하지 않고, 항상 /preview 만 호출합니다.
   - 응답은 innerHTML 이 아니라 textContent 로만 출력합니다.
   ========================================================================== */

"use strict";

// 항상 같은 출처의 로컬 API 하나만 호출합니다.
var PREVIEW_ENDPOINT = "/preview";

// 브라우저 쪽 요청이 영원히 끝나지 않는 것을 막기 위한 상한 시간(ms)입니다.
var CLIENT_TIMEOUT_MS = 15000;

// 요청이 진행 중인지 표시하는 값 (중복 전송 방지용)
var isRequestInFlight = false;

function byId(id) {
  return document.getElementById(id);
}

var previewForm = byId("preview-form");
var urlInput = byId("url-input");
var previewButton = byId("preview-button");
var exampleUrlButton = byId("example-url");

var loadingBox = byId("loading");
var errorMessage = byId("error-message");

var resultCard = byId("result-card");
var resultUrl = byId("result-url");
var resultStatus = byId("result-status");
var resultTime = byId("result-time");
var resultBody = byId("result-body");

/* -------------------------------------------------------------------------
   화면 상태 헬퍼
   ------------------------------------------------------------------------- */

function setLoading(isLoading) {
  isRequestInFlight = isLoading;
  previewButton.disabled = isLoading;
  loadingBox.hidden = !isLoading;
}

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function hideError() {
  errorMessage.textContent = "";
  errorMessage.hidden = true;
}

function hideResult() {
  resultCard.hidden = true;
}

/** 본문이 JSON 이면 보기 좋게 들여쓰고, 아니면 원본 문자열을 그대로 돌려줍니다. */
function formatBody(text) {
  if (typeof text !== "string" || text === "") {
    return "";
  }

  try {
    var parsed = JSON.parse(text);
    if (parsed !== null && typeof parsed === "object") {
      return JSON.stringify(parsed, null, 2);
    }
  } catch (error) {
    // JSON 이 아니면 원본 그대로 보여 줍니다.
  }

  return text;
}

/** 결과 카드를 그립니다. (모든 응답을 똑같은 방식으로 표시합니다.) */
function showResult(data, elapsedMs) {
  // 사용자 입력과 서버 응답은 항상 textContent 로만 넣습니다.
  resultUrl.textContent = typeof data.requested_url === "string" ? data.requested_url : "";
  resultStatus.textContent = String(data.status_code);
  resultTime.textContent = Math.round(elapsedMs) + " ms";
  resultBody.textContent = formatBody(data.content);

  resultCard.hidden = false;
}

/* -------------------------------------------------------------------------
   /preview 요청 보내기
   ------------------------------------------------------------------------- */

function sendPreviewRequest(url) {
  var controller = null;
  var timeoutId = null;
  var options = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url })
  };

  if (typeof AbortController === "function") {
    controller = new AbortController();
    options.signal = controller.signal;
    timeoutId = window.setTimeout(function () {
      controller.abort();
    }, CLIENT_TIMEOUT_MS);
  }

  var startedAt = performance.now();

  return fetch(PREVIEW_ENDPOINT, options)
    .then(function (response) {
      return response
        .json()
        .catch(function () {
          return null;
        })
        .then(function (data) {
          return { data: data, elapsedMs: performance.now() - startedAt };
        });
    })
    .then(function (result) {
      var data = result.data;

      if (!data || typeof data !== "object" || typeof data.status_code !== "number") {
        showError("Could not load a preview for this URL. Please check the address and try again.");
        return;
      }

      hideError();
      showResult(data, result.elapsedMs);
    })
    .catch(function () {
      showError("Could not reach the server. Please try again.");
    })
    .then(function () {
      if (timeoutId !== null) {
        window.clearTimeout(timeoutId);
      }
      setLoading(false);
    });
}

/* -------------------------------------------------------------------------
   이벤트 연결
   ------------------------------------------------------------------------- */

previewForm.addEventListener("submit", function (event) {
  event.preventDefault();

  if (isRequestInFlight) {
    return;
  }

  var url = urlInput.value.trim();

  // 프론트엔드에서는 "비어 있는지" 만 확인합니다.
  if (url === "") {
    hideResult();
    showError("Please enter a URL.");
    urlInput.focus();
    return;
  }

  hideError();
  hideResult();
  setLoading(true);
  sendPreviewRequest(url);
});

// 예시 주소는 입력창을 채우기만 하고 요청을 보내지는 않습니다.
exampleUrlButton.addEventListener("click", function () {
  urlInput.value = exampleUrlButton.textContent.trim();
  urlInput.focus();
});
