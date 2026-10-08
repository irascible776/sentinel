/**
 * Developer 3 (Utkarsh) - Popup UI Logic (popup.js)
 * DTU B.Tech Minor Project (IT401) | Group 138
 */

const GATEWAY_STATS_URL = "http://127.0.0.1:8000/api/v1/stats";

document.addEventListener("DOMContentLoaded", () => {
  const card = document.getElementById("statusCard");
  const indicator = document.getElementById("statusIndicator");
  const statusText = document.getElementById("statusText");
  const statsSection = document.getElementById("statsSection");
  const totalPrompts = document.getElementById("totalPrompts");
  const blockedPrompts = document.getElementById("blockedPrompts");

  fetch(GATEWAY_STATS_URL, { method: "GET" })
    .then(response => {
      if (!response.ok) throw new Error("Gateway returned error");
      return response.json();
    })
    .then(data => {
      card.className = "status-card online";
      statusText.textContent = "Gateway Connected (:8000)";
      statusText.style.color = "var(--success)";
      statsSection.style.display = "block";
      totalPrompts.textContent = data.total_prompts || 0;
      blockedPrompts.textContent = data.blocked_count || 0;
    })
    .catch(() => {
      card.className = "status-card offline";
      statusText.textContent = "Gateway Offline";
      statusText.style.color = "var(--danger)";
      statsSection.style.display = "block";
      totalPrompts.textContent = "—";
      blockedPrompts.textContent = "—";
    });
});
