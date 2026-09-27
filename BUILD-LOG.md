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

At first, I accidentally ran npm install from the repository root. There was no package.json there, so the command failed. I then checked the project structure and found that the actual application was inside the starter/ folder.

After running npm install from starter/, I ran into another problem. better-sqlite3 did not have a prebuilt version for Node 24, which was the version installed on my system. Trying to build it manually also failed because Visual Studio's C++ build tools were not installed.

The repository's .nvmrc file showed that the project was supposed to use Node 22. I tried using nvm-windows to switch to Node 22, but the installer kept failing with errors such as a corrupted download and "not a valid application for this OS platform."

Because of that, I stopped using nvm and removed Node 24. I installed Node 22 LTS directly instead.

After that, I deleted node_modules and package-lock.json and installed the dependencies again from scratch. This time everything worked.

I then ran:
npm run db:reset

and:

npm run dev

Both commands worked successfully, and the server started on localhost:8080, showing the starter shell placeholder.

Main takeaway: The first major problem was not a problem with the repository itself. It was a Node version mismatch.

## Phase 1 — token verification

26-09-2026 18:30 IST

I expected this phase to be fairly straightforward. The main job was to implement the seven checks in verifyAccessToken: split the token, decode it, verify the signature, and check values such as exp, iss, aud, and jti.

While implementing it, I made several small mistakes that caused problems:

I wrote sha26 instead of sha256.
I used a single-quoted string where I needed a template string, so {h}.{p} was treated literally instead of using the actual values.
I wrote aid instead of aud in the issuer/audience check.
I accidentally left out the jti check.
I wrote constnow instead of const now, which caused the module to crash when it loaded.

I also ran into an unexpected VS Code problem. The ESLint extension did not have a proper project configuration, and its automatic fix-on-save was changing ?? into ? ?.

That turned valid JavaScript into invalid syntax every time I saved the file.

I first noticed this happening on the APP_HASH_KEY line and later on the verifyPassword destructuring line.

I disabled ESLint's fix-on-save. When the editor continued to cause problems, I edited the affected lines directly in Notepad so that I could finish the implementation without the editor changing the code again.

After fixing the issues, I ran:
node scripts/check-jwt.js

All checks passed.

Main takeaway: A small mistake such as using aid instead of aud can be worse than an obvious crash because the code may continue running while the security check is simply not doing what it should.

## Phase 2 — caller context and the resolution engine

26-09-2026 21:25 IST

I expected authenticate() to mainly verify the token and look up the user's membership. I also expected permissions.js to translate the resolution rules fairly directly.

My first version of permissions.js had the wrong return format.

I originally made resolve() return an array containing allowed permission names. However, scripts/check-permissions.js expected an object where each permission name contains:

effect
source
reason

The tests also expected specific reason values. For example:

not_a_member when there is no membership record
suspended when the membership exists but is inactive

The problem became clear when the code tried to access .effect on an undefined value.

I also found that organization isolation was stricter than it first appeared.

If a request specifies an organization that is different from the organization in the user's token, the response must be 404, not 403.

A 403 could reveal that the organization exists. A 404 avoids confirming that information.

This check needed to be in context.js because that is the place where both the organization from the token and the organization from the URL are available.

I also had to understand the difference between organization-level and device-level permission resolution.

For organization-level checks, permissions can come from grants across different devices.

For device-level checks, the system considers organization-wide grants and grants that are specifically for that device.

Another important rule was that a deny must be checked before the role baseline or allow grants are considered.

The same ESLint problem from Phase 1 happened again. It changed ?? into ? ? in both context.js and permissions.js.

Disabling the extension did not completely solve the problem, so I again used Notepad to edit the affected lines.

I then changed resolve() so that it creates the complete permission result containing effect, source, and reason for every permission.

The functions can(), assertCan(), and assertCanStartSession() now all use the same decision path through decideOne() instead of having separate permission logic.

I ran:
node scripts/check-permissions.js

Result:
35 passed, 0 failed.

## Phase 3 — orgs, members, invites

27-09-2026 02:20 IST

EI expected the routes in routes/index.js to mostly be plumbing once authentication, context, and permissions were working.

During the first full API test, check-api.js found an important security bug.

The routes use :org in URLs such as:
/v1/orgs/:org/devices

But context.js was checking:
params.orgId

Because the actual parameter was called org, params.orgId was always undefined.

This meant the cross-organization isolation check never actually ran.

As a result, a token belonging to one organization could access another organization's URL and receive a 200 response instead of a 404.

The test that exposed this was specifically checking the situation where an Acme token tries to access Globex.

I also had to determine what should happen when an invitation is accepted by someone who already has a platform account but does not yet belong to that organization.

AUTH-DATA-MODEL.md explains that the existing user should be attached to the organization rather than creating another account.

So acceptInvite first searches for an existing user using the invitation email.

If the user already exists, the system keeps that user's existing password and simply creates the new membership.

If the user does not exist, a new user is created and a password is generated.

I fixed the params.org / params.orgId mismatch.

After the fix, I ran:
node scripts/check-api.js

Result:
66 passed, 0 failed.

Main takeaway: A simple parameter-name mismatch can silently disable a security check and still allow the API to return a successful 200 response.

## Phase 4 — devices and grants

27-09-2026 4:32 IST

One of the main questions in this phase was what should happen when two grants conflict.

For example:

Organization-wide deny
Device-specific allow

My first assumption was that the more specific device-level permission should win. I thought it might work somewhat like CSS specificity, where the more specific rule takes priority.

The tests showed that this was not the correct behavior.

The actual rule is:
An organization-wide DENY always wins.
A device-specific ALLOW cannot override an organization-wide DENY.

The permission check must therefore happen in this order:
Check for deny.
If there is a deny, stop.
Only then consider the role baseline and allow grants.

I also had to make sure the self-grant check in createGrant happens at the correct point.

The condition:
targetUserId === ctx.userId

must be checked even when the caller already has permission to create grants.

The rule is that a user cannot grant a permission to themselves. It is not simply a question of whether they have enough permission to create the grant.

This phase was covered by the existing test suites:

check-permissions.js: 35/35 passed
check-api.js: 66/66 passed

There were no separate failures specific to this phase.

Main takeaway: The permission system is not based on "more specific wins." The important rule is that deny is checked first and always wins.

## Phase 5 — sessions

27-09-2026  7:10 IST

Starting a session requires two different permissions.

First, the user needs:
session:start

Second, they need the permission for the mode they are trying to use, such as:
device:view
device:control
device:terminal

Both permissions must pass before a session can start.

I check session:start first.

If the user does not have that permission, the system returns:
missing_permission

If the user can start sessions but does not have permission for the selected device mode, the system returns:
missing_device_permission

This makes it possible to distinguish between two different problems:

The user cannot start sessions at all.
The user can start sessions but cannot use that particular mode on the device.

The compound session tests in check-api.js passed with this order.

For example:

View session succeeds.
Control session fails with missing_device_permission.
Trying to view a different device fails with missing_permission.

I did not test reversing the order of the two permission checks, but I kept session:start as the first check because the order determines which reason is returned when both permissions could be missing.

## Phase 6 — audit

27-09-2026 8:45 IST

I decided that denied actions should also be recorded in the audit log.

A log containing only successful actions would not answer questions such as:
"Who tried to change something but was denied?"

The auditDenials() function wraps a permission check.

If the permission check fails with a 403, it:
Creates an audit record containing the denial reason.
Throws the original error again.

This keeps the permission check and the audit record connected in the same code path.

For successful actions, the audit entry is created at the same point where the action itself succeeds.

For example, when session:start successfully inserts a new session, the successful audit entry is created immediately afterward.

I did not create a generic "log every request" wrapper because that could result in duplicate audit records.

For example, a route might already perform an internal assertCan() check. A generic request logger could then create another audit record for the same action.

## Phase 7 — the console

27-09-2026 11:00 IST

I expected the console UI to be mostly straightforward because the backend endpoints were already available.

However, I found another Windows-specific issue.

In server/index.js, the DIST constant used:
new URL('../dist/', import.meta.url).pathname

This produced an incorrect path on Windows because of the leading slash and drive letter.

As a result, production page requests returned 404.

The Playwright tests were failing with:
can't find login-email

At first, this looked like a frontend problem. The actual problem was that the server was not serving the built HTML files correctly.

I fixed the path using fileURLToPath(), using the same approach that was already needed in load-db.js.

I also had to account for how the Playwright configuration works.

The tests use:
NODE_ENV=production

That means they use the built dist/ folder rather than the live Vite source.

Therefore, I need to run:
npm run build

before running the tests.

For the console itself, I kept the permission logic on the server rather than creating a role-to-permission table in the frontend.

The UI checks the permission result returned by the server.

For example, navigation items, device buttons, and admin options are displayed only when the relevant permission has:
effect === 'allow'

The grant creation form also gets its permission list from:

Object.keys(session.permissions)

instead of using a hardcoded list.

This means new permissions, such as device:reboot, can appear automatically.

I also found an issue with the device button filtering.

Initially, the UI showed any permission starting with device: as a device-specific button.

This incorrectly included permissions such as:
device:list
device:provision

Those are organization-level capabilities, not actions on one specific device.

I narrowed the filter to the permissions that actually operate on an individual device:
view
control
terminal
file_transfer
update

Finally, I ran:
npm run test

Result:
25 passed, 0 failed.

## Phase 8 — hardening

27-09-2026 12:00 IST

Before submitting, I performed a clean-checkout test.

During this test, I found another Windows-specific issue in the provided code.

The db:reset script used:
rm -f app.db app.db-wal app.db-shm

This is a Unix shell command and does not work reliably on Windows.

I replaced it with a small Node.js one-liner that uses fs.unlinkSync() to delete each file and ignores the files when they don't exist.

This allows the reset script to work on Windows without assuming that a Unix shell is available.

I did not measure anything beyond functional correctness during this final hardening phase.

However, I noticed one possible performance issue in the device-list endpoint.

Currently, the endpoint:

Runs one query to get the devices.
Calls resolveDevices().
That function resolves permissions for each device separately.

This means that if there are n devices, the system can make n additional grant queries instead of using one larger query.

The current implementation is correct, but with more time I would check whether this matters for organizations with a large number of devices and consider changing it to a batched query.

## Open threads

These are the things that were still open at the end of the work:

Refresh / organization context

The refresh process currently restores the user's earliest-joined organization.

It does not necessarily restore the organization the user was last working in.

The reason is that the refresh token only contains the user ID and does not store the organization context.

With more time, I would store the organization along with the refresh token so that reloading the application keeps the exact organization that was active.

Audit pagination

The maximum pagination limit for audit:read is currently 500.

This was a number I chose because the documents did not specify a particular maximum.

Device-list query efficiency

Permission resolution currently performs a separate grant query for each device.

It is correct, but a single batched query would be more efficient, especially for organizations with many devices.

Expired sessions

Sessions have an expires_at value, so the expiration time is stored correctly.

However, there is currently no background process that automatically changes an expired session from:

state = 'active'

to:

state = 'ended'

After the expiration time passes, the session can remain marked as active until something explicitly ends it.

Repository contents

The repository fork provided in the task email contained:

q1-starter/
tools/
starter/

The task was intended to use the starter/ folder.

I did not open or use the contents of q1-starter/ or tools/.

After noticing them, I removed both folders from my working tree and informed the organizers by email.

The removal was committed, but those folders had already appeared in earlier commits because the repository was public.