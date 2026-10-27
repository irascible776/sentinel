# AGENTS.md — Xindia

Permanent, non-negotiable rules for every AI agent and developer working in the Xindia codebase. They apply to every task, conversation, and session.

---

## 0. NEVER ASSUME — LOOK IT UP

Missing information is resolved by investigation, never by guessing.

* Never invent file paths, function names, component names, CSS classes, schema fields, env vars, API routes, or package names. If you have not seen it in the code this session, it does not exist until you find it.
* Before editing any file, read it fully. Before renaming, removing, or changing the signature of anything, grep the whole repo for every usage and handle all of them.
* Resolve unknowns in this order: read the code → read git history/logs → run it and observe. Only if all three fail, state a one-line `ASSUMPTION:` in your output, choose the safest reversible option, and list it in the final report. Never present an assumption as fact.
* Never guess a command. Discover run/build/test/lint commands from `package.json` scripts, config files, and Section 9. If a command is not defined anywhere, say so and propose one.

### 0.5 Verification sources (in priority order)

1. **The codebase is the primary source of truth.** Before relying on any name, route, schema field, helper, or convention, confirm it by reading/grepping the actual code. Double-check every claim you are about to act on against the code, even if you feel sure.
2. **Running it comes second.** If the code does not settle the question, run the app/tests/scripts and observe real behavior.
3. **Web search / official docs only for what the repo cannot answer:** external library or framework APIs, version-specific behavior, third-party services (Razorpay, Google Play policy, MongoDB operators, Next.js Route Handlers), unfamiliar error messages, and anything that may have changed recently. Prefer official documentation over blogs or forums.
4. Check the installed version first (`package.json` / lockfile) so you look up docs for the version actually in use, not the latest.
5. Never let web results override what the codebase actually does. If docs and code disagree, report the conflict instead of silently picking one.
6. Before finalizing, re-verify your key assumptions once more against the code. In the final report, state which source (code / run / docs) confirmed each important point.

---

## 1. AUTONOMOUS EXECUTION & SELF-VERIFICATION

You are expected to run the full verification loop yourself, without asking and without stopping.

* **Run everything yourself:** after every logical change, run all relevant checks: build, lint, static analysis, unit tests, integration/API tests, smoke tests, and any verification scripts in the repo (see Section 9). Do not ask permission to run them. Do not hand them to the user.
* **Fix and re-run until green:** compile errors, build/bundler errors, syntax errors, runtime exceptions, crashes, missing imports, module resolution failures, lint failures, and failing tests are yours to fix immediately and silently. Never ask "Would you like me to fix this?"
* **Run the app when behavior matters:** for anything user-facing or API-facing, start the relevant server(s) and exercise the changed behavior (hit the routes, check responses, check server logs, check the browser console if a UI is involved).
* **Check for leftovers:** after removals/renames, grep for the old names to confirm nothing still references them (dead imports, orphaned CSS, unused routes).
* **Root-cause discipline:** if the same fix fails twice, stop trying variations. Re-read the relevant code end to end, then form a new hypothesis.
* **Never claim success without evidence.** "Done" means you ran the checks and they passed. Report exactly what you ran and what it returned. If something could not be run, say precisely what and why.
* **Autonomy covers errors and mechanical work, not missing information.** Missing information is looked up (Section 0), never guessed.
* **User review is required ONLY before committing or pushing to `git`.** Everything before that proceeds without interruption.
* Only ask the user a question when genuinely blocked after investigation, or when a decision is ambiguous AND consequential (data loss, security, irreversible schema change). Ask one specific question and propose a default.

---

## 2. WORKING METHOD

1. **Explore:** read the relevant files and trace the data flow before touching anything.
2. **Plan:** for any task with more than ~3 edits, write a numbered checklist (`[ ]` pending, `[~]` in progress, `[x]` done). One item in progress at a time. Update it if the plan changes.
3. **Edit surgically:** targeted edits to the specific lines/blocks. Never regenerate a whole file to change part of it. Never silently drop existing code, comments, query params, or handlers. No placeholder code, no "rest unchanged" markers, no TODO stubs.
4. **Re-read** each changed region after editing to confirm it landed correctly.
5. **Verify** per Section 1 after each logical group of changes, not only at the end.
6. **Report** per Section 10.

---

## 3. SCOPE DISCIPLINE

* Do only what was asked. No drive-by refactors, renames, formatting sweeps, or dependency additions.
* Unrelated problems you notice go in the final report under "Noticed but untouched". Do not fix them unless they block the task.
* Never touch files outside the task's scope.
* Match existing conventions (naming, structure, style) in the file you are editing.

---

## 4. 100% REAL END-TO-END IMPLEMENTATION (FEATURE WORK)

This section applies to feature work. Pure UI polish, styling, or refactor tasks do not require schema or backend changes unless the task says so.

* **No stubs, no toast-only buttons, no mock data.** Every button, action, modal, toggle, or filter must be wired end to end:
  Database schema and index → Express controller and service → Next.js Route Handler proxy → live client UI state.
* **No client-side illusions:** no hardcoded placeholder numbers, fake client arrays, or temporary mock promises. Every state mutation persists to and reads from the real MongoDB database.
* **Complete CRUD:** if a feature creates or edits an entity, it also supports listing, filtering, pagination, and deletion/deactivation where applicable.

---

## 5. TECHNOLOGY STACK & ARCHITECTURE

* **Language:** pure JavaScript (`.js` / `.jsx`) only. Do NOT introduce TypeScript (`.ts` / `.tsx`).
* **Styling:** vanilla CSS using CSS custom properties and the existing design tokens (e.g. `admin.css`, `payments.css`, `portfolio.css`, `globals.css`). Strictly NO TailwindCSS, styled-components, or heavy third-party UI libraries unless explicitly requested.
* **Client/server separation:**
  * Client components (`'use client'`) must NEVER call the Express backend (`NEXT_PUBLIC_API_URL`) directly.
  * All client requests go through same-origin Next.js Route Handlers (`/api/admin/...`, `/api/seller/...`, `/api/auth/...`) that read httpOnly session cookies server-side.
  * Never store auth tokens in `localStorage`, `sessionStorage`, or JS-accessible cookies.
* No new dependencies without explicit approval.

---

## 6. SERVER-SIDE AUTHORITY & SECURITY

* **Enforce on the server, never rely on frontend hiding.** Access control and role permissions (`AdminAuthService.requirePermission(...)`, `requireSuperAdmin()`, `requireSeller`) must be enforced on the Express routes themselves.
* **Input sanitization and injection defense:**
  * Always wrap user-supplied regex/search strings with `escapeRegex()` before passing to MongoDB.
  * Explicitly cast query parameters (`planStatus`, `status`, `cityId`, `page`, `limit`, etc.) to their expected primitive types to prevent object/operator injection (`$ne`, `$gt`, etc.).
* **Audit trail:** every administrative mutation (verifying a seller, hiding a product, assigning a plan, creating spotlight overrides, issuing refunds) must record an entry via `AdminAuditService.logAction(...)` into `AdminAuditRecord`, always including `adminId`, `adminUsername`, `action`, `resource`, `targetId`, `changes`, and `ipAddress`. Do not alter the audit service's behavior or invent hashing/signing that it does not already implement.

---

## 7. UNIFORM DATA FLOW & RESILIENT UX

* **Pagination contract for all list endpoints:**
  * Query: `page` (1-based), `limit`, plus optional filters and search.
  * Response: `{ success: true, data: [...], total, page, totalPages }`.
* **Empty and error states:** treat `null`, `undefined`, and empty arrays as valid empty states. Never crash or render raw `NaN` / `undefined`. Provide clear, polished empty-state messaging.
* **Zero regressions:** never silently break or drop existing query parameters, URL state, working hooks, or layout structures.

---

## 8. COMMUNICATION STYLE

* Be terse: one line on what you are about to do, do it, one line on the result. No long preambles, no restating the task.
* **No sugarcoating.** Give direct, technically rigorous feedback. If a requested approach has architectural flaws, security risks, or scalability bottlenecks, say so explicitly alongside the correct solution.
* If you are uncertain or stuck, say so plainly. Do not bluff.

---

## 8.5 AI-HELPER PROTOCOL (Claude Collaboration)

When the user says "ask Claude..." or requests second-opinion planning/debugging:
1. **Never ask for an API key or claim inability to reach Claude.** Use the local CLI tool: `ai-helper ask`.
2. **Automatically gather the 2–4 most relevant ground-truth files** (models, controllers, error logs, or feature directories via `-f`).
3. **Run:** `ai-helper ask --new -f <file1> -f <file2|dir> "<task description>"`.
4. **Read Claude's stdout response**, filter any formatting artifacts, and implement the necessary code changes directly into the repository.

---

## 9. REPO MAP & COMMANDS (FILL IN — agents: if a line is blank, derive it from package.json/config files and report what you found)

```
Backend (Express):        dir: ____________   run: ____________
Frontend (Next.js):       dir: ____________   run: ____________
Build:                    ____________
Lint / static analysis:   ____________
Unit tests:               ____________
Integration / API tests:  ____________
Verification / smoke scripts: ____________
Seed / dev DB setup:      ____________
Required env vars:        see ____________
```

Key locations (fill in): route handlers `____`, services `____`, models/schemas `____`, global styles `____`.

---

## 10. FINAL REPORT FORMAT (end of every task or stage)

* **Changed:** files and a one-line summary each
* **Verified:** the exact commands/scripts run and their outcomes (pass/fail counts)
* **Assumptions:** anything marked `ASSUMPTION`, or "none"
* **Not verified / risks:** anything you could not run or check, and why
* **Noticed but untouched:** unrelated issues spotted

Then, and only then, request the user's review before any `git` commit or push.

---

## RECAP (re-read before starting every task)

1. NEVER assume. Read the file, grep the usages, confirm against the code first (web docs only when the repo cannot answer).
2. Make small, surgical edits. Stay strictly in scope.
3. Run all build, lint, test, and verification scripts yourself after every logical change. Fix and re-run until green. Do not ask, do not stop.
4. Never claim it works without evidence. Report exactly what you ran.
5. Ask the user ONLY before `git commit` / `git push`.
