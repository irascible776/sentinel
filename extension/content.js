/**
 * Developer 3 (Utkarsh) - Content Script (content.js)
 * DTU B.Tech Minor Project (IT401) | Group 138
 *
 * Hooks prompt submissions on ChatGPT, Claude, and demo client.
 * Relays inspection through background.js to bypass CSP restrictions.
 */

(function () {
  let isInspecting = false;

  function showBlockedModal(reason, riskScore, matchedSignatures) {
    const existing = document.getElementById("dtu-gateway-block-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "dtu-gateway-block-overlay";
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(10, 14, 23, 0.85);
      backdrop-filter: blur(4px);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    `;

    const sigs = (matchedSignatures && matchedSignatures.length > 0)
      ? matchedSignatures.join(", ")
      : "Adversarial Pattern Detected";

    overlay.innerHTML = `
      <div style="
        background: #161b26;
        border: 2px solid #ef4444;
        box-shadow: 0 20px 40px rgba(239, 68, 68, 0.3);
        border-radius: 12px;
        padding: 32px;
        max-width: 520px;
        width: 90%;
        color: #f3f4f6;
        text-align: center;
      ">
        <div style="font-size: 52px; margin-bottom: 8px;">🚫</div>
        <h2 style="color: #ef4444; margin: 0 0 12px 0; font-size: 22px; font-weight: 700;">
          Prompt Blocked by AI Security Gateway
        </h2>
        <div style="
          background: #1f293d;
          border-radius: 8px;
          padding: 12px;
          margin-bottom: 16px;
          text-align: left;
          font-size: 13px;
        ">
          <p style="margin: 0 0 6px 0; color: #9ca3af;"><strong>Composite Risk:</strong> <span style="color: #ef4444; font-weight: bold;">${riskScore || 85.0}/100</span></p>
          <p style="margin: 0 0 6px 0; color: #9ca3af;"><strong>Signatures:</strong> <span style="color: #fbbf24;">${sigs}</span></p>
          <p style="margin: 0; color: #d1d5db;"><strong>Reason:</strong> ${reason || "High probability prompt injection / system exfiltration attempt."}</p>
        </div>
        <p style="font-size: 12px; color: #6b7280; margin-bottom: 20px;">
          Protected by DTU AI Security Gateway (IT401 Minor Project Group 138)
        </p>
        <button id="dtu-gateway-dismiss-btn" style="
          padding: 10px 24px;
          background: #ef4444;
          color: white;
          border: none;
          border-radius: 6px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
        ">
          Dismiss & Revise Prompt
        </button>
      </div>
    `;

    document.body.appendChild(overlay);

    const btn = document.getElementById("dtu-gateway-dismiss-btn");
    if (btn) {
      btn.addEventListener("click", () => overlay.remove());
    }
  }

  function getPromptBox() {
    return document.querySelector(
      '#prompt-textarea, div[contenteditable="true"], textarea[placeholder], textarea#user-prompt, input#user-prompt, textarea'
    );
  }

  function interceptSubmission() {
    const promptBox = getPromptBox();
    if (!promptBox) return;

    promptBox.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        const text = promptBox.value || promptBox.innerText || "";
        if (!text.trim() || isInspecting) return;

        e.preventDefault();
        e.stopPropagation();

        isInspecting = true;
        chrome.runtime.sendMessage(
          { action: "INSPECT_PROMPT", prompt: text.trim() },
          function (response) {
            isInspecting = false;
            if (response && response.decision === "BLOCK") {
              showBlockedModal(
                response.reasoning,
                response.risk_score,
                response.matched_signatures
              );
            } else {
              // Allowed: submit the prompt natively
              const submitEv = new KeyboardEvent("keydown", {
                key: "Enter",
                code: "Enter",
                bubbles: true,
                cancelable: true
              });
              Object.defineProperty(submitEv, "shiftKey", { value: false });
              promptBox.dispatchEvent(submitEv);

              // Also check for standard submit button click
              const sendBtn = document.querySelector(
                'button[data-testid="send-button"], button[aria-label="Send prompt"], button#send-btn, button[type="submit"]'
              );
              if (sendBtn && !sendBtn.disabled) {
                sendBtn.click();
              }
            }
          }
        );
      }
    }, true);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", interceptSubmission);
  } else {
    interceptSubmission();
  }
})();
