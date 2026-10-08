/**
 * Developer 3 (Utkarsh) - Background Service Worker (background.js)
 * DTU B.Tech Minor Project (IT401) | Group 138
 *
 * Executes HTTP POST inspection to Gateway using extension host_permissions.
 * CSP-Immune: Not constrained by ChatGPT or Claude Content Security Policies.
 */

const GATEWAY_INSPECT_URL = "http://127.0.0.1:8000/api/v1/inspect";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "INSPECT_PROMPT") {
    const payload = {
      prompt: message.prompt,
      session_id: `ext-${Date.now()}`,
      context_type: "browser_extension"
    };

    fetch(GATEWAY_INSPECT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    })
      .then(response => {
        if (!response.ok) {
          throw new Error(`Gateway returned HTTP ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        sendResponse(data);
      })
      .catch(error => {
        console.warn("[Gateway Extension] Gateway unreachable:", error.message);
        // Fail-open for user flow if gateway is offline
        sendResponse({
          decision: "ALLOW",
          risk_score: 0.0,
          reasoning: "Gateway offline — preflight inspection bypassed.",
          offline: true
        });
      });

    return true; // Keep async message channel open for sendResponse
  }
});
