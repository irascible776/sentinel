# Global Project Directives & Coding Standards — Xindia

This document defines the permanent, non-negotiable rules for all AI agents and developers working across the Xindia codebase. These instructions persist across all conversations, tasks, and sessions.

---

## 1. Autonomous Execution & Verification (Zero Unnecessary User Prompts)

* **NEVER pause or ask for user review during:**
  * Compile errors, build errors, or bundler issues
  * Syntax errors, runtime exceptions, or crashes
  * Missing import checks or module resolution failures
  * Static analysis, lint fixes, or mechanical refactoring
  * Any internal research, file exploration, or code auditing
  * Automated testing, smoke testing, or API route verification
* **Autonomous Resolution:** Always fix compilation issues, missing imports, syntax bugs, and broken logic independently and immediately. Do not ask "Would you like me to fix this error?" — simply fix it, verify it, and proceed.
* **When User Review IS Required:** Request the user's explicit review and approval **ONLY** before committing or pushing changes to `git`.

---

## 2. 100% Real End-to-End Implementation — Zero Stubs, Zero Fakes

* **No "Toast-Only" Stubs or Mock Data:** Every button, action, modal, toggle, or filter must be wired end-to-end:
  $$\text{Database Schema \& Index} \longrightarrow \text{Express Controller \& Service} \longrightarrow \text{Next.js Route Handler Proxy} \longrightarrow \text{Live Client UI State}$$
* **No Client-Side Illusions:** Never use hardcoded placeholder numbers, fake client arrays, or temporary mock promises. Every state mutation must persist to and read from the real MongoDB database.
* **Complete CRUD:** If a feature allows creating or editing an entity, it must also support listing, filtering, pagination, and deletion/deactivation where applicable.

---

## 3. Strict Codebase Architecture & Technology Stack

* **Language:** Pure **JavaScript (`.js` / `.jsx`)** only. Do NOT introduce TypeScript (`.ts` / `.tsx`).
* **Styling:**
  * Vanilla CSS using **CSS custom properties and existing design tokens** (e.g. `admin.css`, `payments.css`, `portfolio.css`, `globals.css`).
  * **Strictly NO TailwindCSS**, styled-components, or heavy third-party UI component libraries unless explicitly requested.
* **Client / Server Security Separation:**
  * Client components (`'use client'`) must **NEVER** call the Express backend (`NEXT_PUBLIC_API_URL`) directly.
  * All client requests must go through same-origin Next.js Route Handlers (`/api/admin/...`, `/api/seller/...`, `/api/auth/...`) that read httpOnly session cookies server-side.
  * Never store auth tokens in `localStorage`, `sessionStorage`, or accessible cookies.

---

## 4. Server-Side Authority, Security & Auditing

* **Authoritative Server Enforcement:** Never rely on frontend cosmetic hides. Access control and role permissions (`AdminAuthService.requirePermission(...)`, `requireSuperAdmin()`, `requireSeller`) must be strictly enforced on Express routes.
* **Input Sanitization & Injection Defense:**
  * Always sanitize regex queries with `escapeRegex()` before passing to MongoDB.
  * Explicitly cast query parameters (`planStatus`, `status`, `cityId`, `page`, `limit`) to prevent MongoDB object/operator injection (`$ne`, `$gt`).
* **Immutable Audit Trail:**
  * Every single administrative mutation (verifying a seller, hiding a product, assigning a plan, creating spotlight overrides, issuing refunds) must record a cryptographic audit entry via `AdminAuditService.logAction(...)` in `AdminAuditRecord`.
  * Always record `adminId`, `adminUsername`, `action`, `resource`, `targetId`, `changes`, and `ipAddress`.

---

## 5. Uniform Data Flow & Resilient UX

* **Standardized Pagination:** All list endpoints must follow the uniform query and response contract:
  * Query: `page` (1-based), `limit`, plus optional filters and search.
  * Response: `{ success: true, data: [...], total, page, totalPages }`.
* **Graceful Empty State Handling:**
  * Treat `null`, `undefined`, or empty arrays as valid empty states — never let them crash the page or display raw `NaN` / `undefined`.
  * Provide polished, informative empty state illustrations and clear messaging.
* **Zero Regressions:** Never silently break or drop existing query parameters, URL state, working hooks, or layout structures.

---

## 6. Communication Style

* **No Sugarcoating:** Always give direct, technically rigorous feedback. If a requested approach has architectural flaws, security risks, or scalability bottlenecks, highlight them explicitly alongside the correct solution.
