# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

26-09-2026 16:27 IST
Ran npm install from repo root by mistake — got ENOENT, no package.json there;
the actual app lives in starter/. Re-ran from starter/, hit a native build
failure: better-sqlite3 has no prebuilt binary for Node 24 (my installed version),
and node-gyp couldn't compile it from source without Visual Studio's
C++ build tools. The repo's .nvmrc pins Node 22. Tried nvm-windows to switch
the installer kept failing (corrupted binary, "not a valid application for
this OS platform"). Gave up on nvm, uninstalled Node 24 entirely, installed
Node 22 LTS directly instead. Deleted node_modules and package-lock.json,
reinstalled clean — worked. npm run db:reset and npm run dev both succeeded,
server came up on localhost:8080 showing the starter shell placeholder.
Note: the environment was the first real obstacle, before any actual code 
worth remembering that "it doesn't install" is often a version mismatch, not
a broken repo.

## Phase 1 — token verification

26-09-2026 18:30 IST
Expected: writing the 7 checks in verifyAccessToken would be mostly mechanical
once I understood the shape — split the token, decode, verify signature,
check exp/iss/aud/jti.
Observed: introduced several bugs while typing it in that didn't show up
immediately — 'sha26' instead of 'sha256', a single-quoted template string
that never interpolated ({h}.{p} literally instead of the actual values),
'aid' instead of 'aud' in the issuer/audience check, a missing jti check I'd
dropped, and a `constnow` typo (no space) that crashed the module load
entirely. On top of that, VS Code's ESLint extension had no project config,
so its fix-on-save was silently rewriting `??` into `? ?` (inserting a space)
every time I saved — which kept reintroducing a SyntaxError even right after
I'd fixed it, because the editor was actively undoing the fix.
Changed: fixed each typo one at a time, disabled ESLint's fix-on-save, and
when the editor still corrupted the file, edited the line directly in
Notepad to bypass it. node scripts/check-jwt.js now passes.
Note: a wrong claim name (aid vs aud) is more dangerous than a crash — it
fails silently instead of loudly. Also: tooling that "fixes" code it doesn't
understand is worse than tooling that just complains.

## Phase 2 — caller context and the resolution engine
26-09-2026 21:25 IST

Expected: authenticate() would just be "verify the token, look up the membership,"
and permissions.js would be a straightforward translation of the resolution rules
into code.

Observed several things that weren't obvious going in:
- Org isolation is stricter than it reads: a request naming a different org than
  the token's org claim has to be a 404, not a 403 — a 403 would confirm the org
  exists at all, which is itself a leak. That check has to live in context.js,
  since it's the only place that sees both the token's org claim and the URL's
  org param together.
- My first version of permissions.js had the wrong return shape entirely.
  resolve() returned an array of allowed permission strings, but the actual
  contract (confirmed by scripts/check-permissions.js) is an object keyed by
  permission name, each holding { effect, source, reason } — with specific
  reason strings ('not_a_member' for no membership row at all, vs 'suspended'
  for an inactive one; 'missing_permission' vs 'missing_device_permission' in
  the compound session-start check). The crash from calling .effect on
  undefined is what exposed this.
- Org-level vs device-level resolution isn't a simple filter: org-level (nav
  gating) has to union permissions across every device the user has grants on,
  while a device-level check only sees org-wide grants plus grants scoped to
  that exact device.
- Deny has to be checked before role baseline and allow grants are even
  considered — not layered on top afterward.
- Hit VS Code's ESLint extension rewriting `??` into `? ?` on every save
  (no project ESLint config exists, so it was running with a stale default
  that doesn't parse nullish coalescing). This silently reintroduced the same
  SyntaxError three separate times, in auth.js, context.js, and permissions.js.
  Disabling the extension didn't fully stop it; ended up editing the affected
  lines directly in Notepad to bypass the editor entirely.
- scripts/load-db.js has a genuine Windows bug in code that was provided,
  not written by me: `new URL(p, import.meta.url).pathname` produces a doubled
  drive letter (C:\C:\Users\...) on Windows. Fixed by switching to
  fileURLToPath(). Worth flagging since it touches a file outside the
  "yours to write" boundary.
- After the load-db fix, confirmed the personalisation overlay adds a
  'reviewer' role (rank 35) and a 'device:reboot' permission, neither
  documented anywhere — exactly the case D19 exists for. Because
  permissions.js reads role/permission names from the database rather than
  hardcoding the documented five roles and nineteen permissions, this worked
  automatically with no special-casing needed.

Changed: rewrote resolve() to build the full { effect, source, reason } map for
every permission key; had can()/assertCan()/assertCanStartSession() read from
that single decision path (decideOne) rather than duplicating logic.

## Phase 3 — orgs, members, invites
27-09-2026 02:20 IST

Expected: routes/index.js would mostly be plumbing once auth, context, and
permissions were solid — read params, call assertCan, query the db, respond.
Observed: the first full pass had one serious bug that check-api.js caught
immediately — the cross-org isolation check in context.js compared
params.orgId, but the router's actual parameter name (from the :org segment
in routes like /v1/orgs/:org/devices) is params.org. Since params.orgId was
always undefined, the check silently never fired, and a token scoped to one
org could address any org's URL, exactly the vulnerability the whole
structural-isolation design was meant to prevent. It only surfaced because
the test suite specifically checks "Acme token against Globex -> 404."
Changed: fixed the param name mismatch in context.js.
Note: node scripts/check-api.js, 66 passed, 0 failed. A parameter name
typo that silently disables a security check and still returns 200 is a
worse failure mode than a crash, it never even hinted anything was wrong
until the specific isolation test caught it.

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
