import {
    issueAccessToken,
    verifyPassword,
    hashPassword,
    newRefreshToken,
    hashRefreshToken,
    newInviteToken,
    hashInviteToken,
    REFRESH_TTL_SECONDS,
} from '../auth.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import {
    badRequest,
    unauthenticated,
    forbidden,
    notFound,
    conflict,
    gone,
    deviceBusy,
    normalizeTs,
    send,
    HttpError,
} from '../http.js';
import { resolve, resolveDevices, can, assertCan, assertMayGrant, assertCanStartSession, MODE_PERMISSION } from '../permissions.js';
import { roleRanks, assertRoleExists, assertCanModify, assertNotLastOwner, endActiveSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';

function activeOrgsFor(db, userId) {
    return db
        .prepare(
            `SELECT o.id, o.name, o.theme, m.role
       FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
       ORDER BY m.joined_at ASC`
        )
        .all(userId);
}

function parseCookies(req) {
    const header = req.headers.cookie ?? '';
    const out = {};
    for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
    return out;
}

function setRefreshCookie(res, raw, maxAgeSeconds) {
    res.setHeader('Set-Cookie', `refresh_token=${raw}; HttpOnly; SameSite=Strict; Path=/v1/auth; Max-Age=${maxAgeSeconds}`);
}

function issueSession(db, secret, res, userId, membership) {
    const accessToken = issueAccessToken({ userId, orgId: membership.org_id, role: membership.role, permVersion: membership.perm_version },
        secret
    );
    const raw = newRefreshToken();
    db.prepare(
        `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
     VALUES (?,?,?,?,?)`
    ).run(newId('rt'), userId, hashRefreshToken(raw), newId('fam'), new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());
    setRefreshCookie(res, raw, REFRESH_TTL_SECONDS);
    return accessToken;
}

// --- auth --------------------------------------------------------------

async function login(ctx, params, res) {
    const { email, password, orgId } = ctx.body;
    if (!email || !password) throw badRequest('email and password are required');

    const user = ctx.db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase());
    if (!user || !verifyPassword(password, user.password_hash)) {
        throw unauthenticated('invalid email or password');
    }

    const orgs = activeOrgsFor(ctx.db, user.id);
    if (orgs.length === 0) throw unauthenticated('no active memberships');

    const chosen = orgId ? orgs.find((o) => o.id === orgId) : orgs[0];
    if (!chosen) throw unauthenticated('not a member of that organization');

    const membership = ctx.db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(chosen.id, user.id);
    const token = issueSession(ctx.db, ctx.secret, res, user.id, membership);
    const { permissions } = resolve(ctx.db, { userId: user.id, orgId: chosen.id });

    send(res, 200, {
        token,
        userId: user.id,
        orgId: chosen.id,
        role: membership.role,
        orgs: orgs.map((o) => ({ id: o.id, name: o.name, theme: o.theme })),
        permissions,
    });
}

async function refresh(ctx, params, res) {
    const cookies = parseCookies(ctx.req);
    const raw = cookies.refresh_token;
    if (!raw) throw unauthenticated('missing refresh token');

    const hash = hashRefreshToken(raw);
    const row = ctx.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hash);
    if (!row || row.revoked_at || new Date(row.expires_at) <= new Date()) {
        throw unauthenticated('invalid refresh token');
    }
    ctx.db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(nowIso(), row.id);

    const orgs = activeOrgsFor(ctx.db, row.user_id);
    const chosen = orgs[0];
    if (!chosen) throw unauthenticated('no active memberships');
    const membership = ctx.db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(chosen.id, row.user_id);

    const accessToken = issueSession(ctx.db, ctx.secret, res, row.user_id, membership);
    send(res, 200, { token: accessToken });
}

async function switchOrg(ctx, params, res) {
    const { orgId } = ctx.body;
    if (!orgId) throw badRequest('orgId is required');

    const membership = ctx.db
        .prepare(
            `SELECT m.* FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.org_id = ? AND m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
        )
        .get(orgId, ctx.userId);
    if (!membership) throw notFound();

    const accessToken = issueAccessToken({ userId: ctx.userId, orgId, role: membership.role, permVersion: membership.perm_version },
        ctx.secret
    );
    send(res, 200, { token: accessToken, role: membership.role, orgId });
}

async function me(ctx, params, res) {
    const orgs = activeOrgsFor(ctx.db, ctx.userId);
    const { permissions } = resolve(ctx.db, { userId: ctx.userId, orgId: ctx.orgId });
    send(res, 200, {
        userId: ctx.userId,
        orgId: ctx.orgId,
        role: ctx.role,
        orgs: orgs.map((o) => ({ id: o.id, name: o.name, theme: o.theme })),
        permissions,
    });
}

// --- orgs ----------------------------------------------------------------

async function listOrgs(ctx, params, res) {
    const orgs = activeOrgsFor(ctx.db, ctx.userId);
    send(res, 200, { orgs: orgs.map((o) => ({ id: o.id, name: o.name, theme: o.theme, role: o.role })) });
}

async function createOrg(ctx, params, res) {
    const { name, theme } = ctx.body;
    if (!name || typeof name !== 'string') throw badRequest('name is required');

    const id = newId('org');
    ctx.db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?,?,?)').run(id, name, theme ?? 'default');
    ctx.db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?,?,?,'owner','active',?)`
    ).run(newId('mem'), id, ctx.userId, nowIso());

    send(res, 201, { id, name, theme: theme ?? 'default', role: 'owner' });
}

async function updateOrg(ctx, params, res) {
    assertCan(ctx.db, ctx, 'org:update');
    const org = ctx.db.prepare('SELECT * FROM organizations WHERE id = ? AND deleted_at IS NULL').get(ctx.orgId);
    if (!org) throw notFound();

    const { name, theme, maxSessionMinutes } = ctx.body;
    ctx.db.prepare(
        'UPDATE organizations SET name = COALESCE(?, name), theme = COALESCE(?, theme), max_session_minutes = COALESCE(?, max_session_minutes) WHERE id = ?'
    ).run(name ?? null, theme ?? null, maxSessionMinutes ?? null, ctx.orgId);

    send(res, 200, { id: ctx.orgId });
}

async function deleteOrg(ctx, params, res) {
    assertCan(ctx.db, ctx, 'org:delete');
    ctx.db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), ctx.orgId);
    send(res, 200, { id: ctx.orgId });
}

// --- members ---------------------------------------------------------------

async function listMembers(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:read');
    const rows = ctx.db
        .prepare(
            `SELECT m.user_id, m.role, m.status, m.joined_at, u.email, u.name
       FROM memberships m JOIN users u ON u.id = m.user_id
       WHERE m.org_id = ?`
        )
        .all(ctx.orgId);
    send(res, 200, { members: rows });
}

async function updateMemberRole(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:role:update');
    const targetUserId = params.userId;
    if (targetUserId === ctx.userId) throw new HttpError(403, 'SELF_ROLE_CHANGE', 'you cannot change your own role');

    const target = ctx.db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    const { role: newRole } = ctx.body;
    assertRoleExists(ctx.db, newRole);
    assertCanModify(ctx.db, ctx.role, target.role);

    const ranks = roleRanks(ctx.db);
    if (newRole === 'owner' && ctx.role !== 'owner') throw forbidden('only an owner may confer owner');
    if (ctx.role !== 'owner' && ranks[newRole] >= ranks[ctx.role]) {
        throw forbidden('cannot assign a role you could not assign yourself', 'insufficient_rank');
    }
    if (target.role === 'owner' && newRole !== 'owner') assertNotLastOwner(ctx.db, ctx.orgId, targetUserId);

    ctx.db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(newRole, ctx.orgId, targetUserId);
    bumpPermVersion(ctx.db, { orgId: ctx.orgId, userId: targetUserId });

    send(res, 200, { userId: targetUserId, role: newRole });
}

async function suspendMember(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:remove');
    const targetUserId = params.userId;
    const target = ctx.db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    assertCanModify(ctx.db, ctx.role, target.role);
    if (target.role === 'owner') assertNotLastOwner(ctx.db, ctx.orgId, targetUserId);

    ctx.db.prepare("UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, targetUserId);
    bumpPermVersion(ctx.db, { orgId: ctx.orgId, userId: targetUserId });
    endActiveSessions(ctx.db, { orgId: ctx.orgId, userId: targetUserId, reason: 'user_suspended' });

    send(res, 200, { userId: targetUserId, status: 'suspended' });
}

async function reinstateMember(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:remove');
    const targetUserId = params.userId;
    const target = ctx.db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    ctx.db.prepare("UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, targetUserId);
    bumpPermVersion(ctx.db, { orgId: ctx.orgId, userId: targetUserId });

    send(res, 200, { userId: targetUserId, status: 'active' });
}

async function removeMember(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:remove');
    const targetUserId = params.userId;
    const target = ctx.db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    assertCanModify(ctx.db, ctx.role, target.role);
    if (target.role === 'owner') assertNotLastOwner(ctx.db, ctx.orgId, targetUserId);

    ctx.db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, targetUserId);
    bumpPermVersion(ctx.db, { orgId: ctx.orgId, userId: targetUserId });
    endActiveSessions(ctx.db, { orgId: ctx.orgId, userId: targetUserId, reason: 'membership_removed' });

    send(res, 200, { userId: targetUserId, status: 'removed' });
}

async function leaveOrg(ctx, params, res) {
    if (ctx.role === 'owner') assertNotLastOwner(ctx.db, ctx.orgId, ctx.userId);

    ctx.db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, ctx.userId);
    bumpPermVersion(ctx.db, { orgId: ctx.orgId, userId: ctx.userId });
    endActiveSessions(ctx.db, { orgId: ctx.orgId, userId: ctx.userId, reason: 'membership_removed' });

    send(res, 200, { userId: ctx.userId, status: 'removed' });
}

// --- invites -----------------------------------------------------------

async function createInvite(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:invite');
    const { email, role } = ctx.body;
    if (!email || !role) throw badRequest('email and role are required');
    assertRoleExists(ctx.db, role);

    const ranks = roleRanks(ctx.db);
    if (role === 'owner' && ctx.role !== 'owner') throw forbidden('only an owner may invite as owner');
    if (ctx.role !== 'owner' && ranks[role] >= ranks[ctx.role]) {
        throw forbidden('cannot invite a role you could not assign', 'insufficient_rank');
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    const existingMember = ctx.db
        .prepare(
            `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
       WHERE m.org_id = ? AND u.email = ? AND m.status = 'active'`
        )
        .get(ctx.orgId, normalizedEmail);
    if (existingMember) throw conflict('already an active member');

    const existingInvite = ctx.db
        .prepare('SELECT 1 FROM invites WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL')
        .get(ctx.orgId, normalizedEmail);
    if (existingInvite) throw conflict('an invite is already pending for this email');

    const raw = newInviteToken();
    const id = newId('inv');
    const expiresAt = new Date(Date.now() + 7 * 86400000).toISOString();

    ctx.db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?,?,?,?,?,?,?)`
    ).run(id, ctx.orgId, normalizedEmail, role, hashInviteToken(raw), ctx.userId, expiresAt);

    send(res, 201, { id, inviteToken: raw, expiresAt });
}

async function listInvites(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:invite');
    const rows = ctx.db
        .prepare('SELECT id, email, role, expires_at, accepted_at, revoked_at FROM invites WHERE org_id = ?')
        .all(ctx.orgId);
    send(res, 200, { invites: rows });
}

async function revokeInvite(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:invite');
    const invite = ctx.db
        .prepare('SELECT * FROM invites WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL')
        .get(params.id, ctx.orgId);
    if (!invite) throw notFound();
    ctx.db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), invite.id);
    send(res, 200, { id: invite.id });
}

async function peekInvite(ctx, params, res) {
    const hash = hashInviteToken(params.token);
    const invite = ctx.db
        .prepare(`SELECT i.*, o.name AS org_name FROM invites i JOIN organizations o ON o.id = i.org_id WHERE i.token_hash = ?`)
        .get(hash);
    if (!invite) throw notFound();
    if (invite.revoked_at || invite.accepted_at || new Date(invite.expires_at) <= new Date()) throw gone();

    send(res, 200, { orgName: invite.org_name, role: invite.role, email: invite.email, expiresAt: invite.expires_at });
}

async function acceptInvite(ctx, params, res) {
    const hash = hashInviteToken(params.token);
    const invite = ctx.db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(hash);
    if (!invite) throw notFound();
    if (invite.accepted_at) throw conflict('invite already accepted');
    if (invite.revoked_at || new Date(invite.expires_at) <= new Date()) throw gone();

    let user = ctx.db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
    const { name, password } = ctx.body;

    const accept = ctx.db.transaction(() => {
        if (!user) {
            if (!name || !password) throw badRequest('name and password are required');
            const userId = newId('usr');
            ctx.db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?,?,?,?)')
                .run(userId, invite.email, name, hashPassword(password));
            user = { id: userId, email: invite.email, name };
        }

        const existingMembership = ctx.db
            .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
            .get(invite.org_id, user.id);

        if (existingMembership) {
            ctx.db.prepare("UPDATE memberships SET role = ?, status = 'active', joined_at = ? WHERE org_id = ? AND user_id = ?")
                .run(invite.role, nowIso(), invite.org_id, user.id);
        } else {
            ctx.db.prepare(
                `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?,?,?,?,'active',?,?)`
            ).run(newId('mem'), invite.org_id, user.id, invite.role, invite.invited_by, nowIso());
        }

        ctx.db.prepare('UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?').run(nowIso(), user.id, invite.id);
    });
    accept();

    send(res, 200, { userId: user.id, orgId: invite.org_id, role: invite.role });
}

// --- devices -----------------------------------------------------------

async function listDevices(ctx, params, res) {
    assertCan(ctx.db, ctx, 'device:list');
    const rows = ctx.db.prepare('SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL').all(ctx.orgId);
    const { byDevice } = resolveDevices(ctx.db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: rows.map((d) => d.id) });

    const devices = rows
        .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
        .map((d) => ({ id: d.id, name: d.name, kind: d.kind, online: !!d.online, permissions: byDevice[d.id] }));

    send(res, 200, { devices });
}

async function getDevice(ctx, params, res) {
    const device = ctx.db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(params.id, ctx.orgId);
    if (!device) throw notFound();

    const { permissions } = resolve(ctx.db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id });
    if (permissions['device:view'].effect !== 'allow') throw notFound();

    send(res, 200, { id: device.id, name: device.name, kind: device.kind, online: !!device.online, permissions });
}

async function createDevice(ctx, params, res) {
    assertCan(ctx.db, ctx, 'device:provision');
    const { name, kind } = ctx.body;
    if (!name || !kind) throw badRequest('name and kind are required');

    const id = newId('dev');
    ctx.db.prepare('INSERT INTO devices (id, org_id, name, kind) VALUES (?,?,?,?)').run(id, ctx.orgId, name, kind);
    send(res, 201, { id, name, kind, online: false });
}

async function updateDevice(ctx, params, res) {
    assertCan(ctx.db, ctx, 'device:update');
    const device = ctx.db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(params.id, ctx.orgId);
    if (!device) throw notFound();

    ctx.db.prepare('UPDATE devices SET name = COALESCE(?, name) WHERE id = ?').run(ctx.body.name ?? null, device.id);
    send(res, 200, { id: device.id });
}

async function deleteDevice(ctx, params, res) {
    assertCan(ctx.db, ctx, 'device:provision');
    const device = ctx.db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(params.id, ctx.orgId);
    if (!device) throw notFound();

    ctx.db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), device.id);
    endActiveSessions(ctx.db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
    send(res, 200, { id: device.id });
}

async function transferDevice(ctx, params, res) {
    assertCan(ctx.db, ctx, 'device:provision');
    const device = ctx.db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(params.id, ctx.orgId);
    if (!device) throw notFound();

    const { targetOrgId } = ctx.body;
    if (!targetOrgId) throw badRequest('targetOrgId is required');

    const targetMembership = ctx.db
        .prepare(
            `SELECT m.* FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.org_id = ? AND m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
        )
        .get(targetOrgId, ctx.userId);
    if (!targetMembership) throw notFound();

    const targetDecision = resolve(ctx.db, { userId: ctx.userId, orgId: targetOrgId }).permissions['device:provision'];
    if (targetDecision.effect !== 'allow') throw forbidden('missing permission in target org', targetDecision.reason);

    endActiveSessions(ctx.db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
    ctx.db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, device.id);

    send(res, 200, { id: device.id, orgId: targetOrgId });
}

// --- grants ------------------------------------------------------------

async function createGrant(ctx, params, res) {
    const { userId: targetUserId, deviceId, effect, permissions, startsAt, expiresAt } = ctx.body;

    if (!Array.isArray(permissions) || permissions.length === 0) throw badRequest('permissions must be a non-empty array');
    if (effect !== 'allow' && effect !== 'deny') throw badRequest('effect must be allow or deny');

    for (const p of permissions) {
        const known = ctx.db.prepare('SELECT 1 FROM permission_patterns WHERE pattern = ?').get(p);
        if (!known) throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
    }

    if (deviceId) {
        const device = ctx.db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId);
        if (!device) throw notFound();
    }

    const target = ctx.db
        .prepare("SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'")
        .get(ctx.orgId, targetUserId);
    if (!target) throw notFound();

    if (targetUserId === ctx.userId) throw forbidden('cannot grant to yourself', 'self_grant');

    const start = normalizeTs(startsAt, 'startsAt');
    const expiry = normalizeTs(expiresAt, 'expiresAt');
    if (expiry && new Date(expiry) <= new Date()) throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt must be in the future');

    assertMayGrant(ctx.db, ctx, permissions, deviceId ?? null);

    const id = newId('grt');
    ctx.db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?,?,?,?,?,?,?,?)`
    ).run(id, ctx.orgId, targetUserId, deviceId ?? null, effect, start, expiry, ctx.userId);
    for (const p of permissions) {
        ctx.db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?,?)').run(id, p);
    }

    bumpPermVersion(ctx.db, { orgId: ctx.orgId, userId: targetUserId });
    audit(ctx.db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant:create', targetType: 'grant', targetId: id, result: 'allow', requestId: ctx.requestId });

    send(res, 201, { id });
}

async function listGrants(ctx, params, res) {
    assertCan(ctx.db, ctx, 'user:read');
    const targetUserId = ctx.query.get('userId');
    const rows = targetUserId ?
        ctx.db.prepare('SELECT * FROM grants WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL').all(ctx.orgId, targetUserId) :
        ctx.db.prepare('SELECT * FROM grants WHERE org_id = ? AND revoked_at IS NULL').all(ctx.orgId);
    send(res, 200, { grants: rows });
}

async function revokeGrant(ctx, params, res) {
    assertCan(ctx.db, ctx, 'grant:revoke');
    const grant = ctx.db.prepare('SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(params.id, ctx.orgId);
    if (!grant) throw notFound();

    ctx.db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), grant.id);
    bumpPermVersion(ctx.db, { orgId: ctx.orgId, userId: grant.user_id });
    audit(ctx.db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant:revoke', targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { id: grant.id });
}

// --- sessions ------------------------------------------------------------

async function startSession(ctx, params, res) {
    const { deviceId, mode } = ctx.body;
    if (!deviceId || !MODE_PERMISSION[mode]) throw badRequest('deviceId and a valid mode are required');

    const device = ctx.db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId);
    if (!device) throw notFound();

    auditDenials(ctx.db, ctx, { action: 'session:start', targetType: 'device', targetId: deviceId }, () => {
        assertCanStartSession(ctx.db, ctx, mode, deviceId);
    });

    const id = newId('ses');
    const startedAt = nowIso();
    const expiresAt = sessionExpiry(ctx.db, ctx.orgId, new Date(startedAt));
    const authority = snapshotAuthority(ctx.db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

    try {
        ctx.db.prepare(
            `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
       VALUES (?,?,?,?,?,'active',?,?,?)`
        ).run(id, ctx.orgId, ctx.userId, deviceId, mode, JSON.stringify(authority), startedAt, expiresAt);
    } catch (err) {
        if (String(err.message).includes('UNIQUE')) {
            const holder = ctx.db
                .prepare("SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')")
                .get(deviceId);
            throw deviceBusy(`device already has an exclusive session${holder ? `: ${holder.id}` : ''}`);
    }
    throw err;
  }

  audit(ctx.db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session:start', targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId });

  send(res, 201, { id, deviceId, mode, state: 'active', startedAt, expiresAt });
}

async function listSessions(ctx, params, res) {
  assertCan(ctx.db, ctx, 'session:view');
  const rows = ctx.db.prepare('SELECT * FROM sessions WHERE org_id = ?').all(ctx.orgId);
  send(res, 200, { sessions: rows });
}

async function getSession(ctx, params, res) {
  const session = ctx.db.prepare('SELECT * FROM sessions WHERE id = ? AND org_id = ?').get(params.id, ctx.orgId);
  if (!session) throw notFound();

  const isParticipant = session.user_id === ctx.userId;
  if (!isParticipant && !can(ctx.db, ctx, 'session:view')) throw notFound();

  send(res, 200, session);
}

async function endSession(ctx, params, res) {
  const session = ctx.db.prepare("SELECT * FROM sessions WHERE id = ? AND org_id = ? AND state = 'active'").get(params.id, ctx.orgId);
  if (!session) throw notFound();

  const isOwner = session.user_id === ctx.userId;
  if (!isOwner && !can(ctx.db, ctx, 'session:terminate')) throw forbidden('cannot terminate this session');

  const reason = isOwner ? 'user_stopped' : 'admin_terminated';
  ctx.db.prepare("UPDATE sessions SET state='ended', end_reason=?, ended_at=? WHERE id=?").run(reason, nowIso(), session.id);

  send(res, 200, { id: session.id, state: 'ended', end_reason: reason });
}

// --- effective + audit ---------------------------------------------------

async function getEffective(ctx, params, res) {
  if (params.userId !== ctx.userId && !can(ctx.db, ctx, 'user:read')) throw forbidden("cannot view this user's effective permissions");
  send(res, 200, resolve(ctx.db, { userId: params.userId, orgId: ctx.orgId }));
}

async function listAudit(ctx, params, res) {
  assertCan(ctx.db, ctx, 'audit:read');

  const limitRaw = ctx.query.get('limit');
  const offsetRaw = ctx.query.get('offset');
  const limit = limitRaw === null ? 50 : Number(limitRaw);
  const offset = offsetRaw === null ? 0 : Number(offsetRaw);

  if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw badRequest('limit must be between 1 and 500');
  if (!Number.isInteger(offset) || offset < 0) throw badRequest('offset must be >= 0');

  const rows = ctx.db.prepare('SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?').all(ctx.orgId, limit, offset);
  send(res, 200, { events: rows });
}

// --- registration --------------------------------------------------------

export function registerRoutes(router, deps) {
  void deps;

  router.post('/v1/auth/login', login);
  router.post('/v1/auth/refresh', refresh);
  router.post('/v1/auth/token', switchOrg);
  router.get('/v1/auth/me', me);

  router.get('/v1/orgs', listOrgs);
  router.post('/v1/orgs', createOrg);
  router.patch('/v1/orgs/:org', updateOrg);
  router.delete('/v1/orgs/:org', deleteOrg);

  router.get('/v1/orgs/:org/members', listMembers);
  router.delete('/v1/orgs/:org/members/me', leaveOrg);
  router.patch('/v1/orgs/:org/members/:userId', updateMemberRole);
  router.post('/v1/orgs/:org/members/:userId/suspend', suspendMember);
  router.delete('/v1/orgs/:org/members/:userId/suspend', reinstateMember);
  router.delete('/v1/orgs/:org/members/:userId', removeMember);

  router.post('/v1/orgs/:org/invites', createInvite);
  router.get('/v1/orgs/:org/invites', listInvites);
  router.delete('/v1/orgs/:org/invites/:id', revokeInvite);
  router.get('/v1/invites/:token', peekInvite);
  router.post('/v1/invites/:token/accept', acceptInvite);

  router.get('/v1/orgs/:org/devices', listDevices);
  router.get('/v1/orgs/:org/devices/:id', getDevice);
  router.post('/v1/orgs/:org/devices', createDevice);
  router.patch('/v1/orgs/:org/devices/:id', updateDevice);
  router.delete('/v1/orgs/:org/devices/:id', deleteDevice);
  router.post('/v1/orgs/:org/devices/:id/transfer', transferDevice);

  router.post('/v1/orgs/:org/grants', createGrant);
  router.get('/v1/orgs/:org/grants', listGrants);
  router.delete('/v1/orgs/:org/grants/:id', revokeGrant);

  router.post('/v1/orgs/:org/sessions', startSession);
  router.get('/v1/orgs/:org/sessions', listSessions);
  router.get('/v1/sessions/:id', getSession);
  router.delete('/v1/sessions/:id', endSession);

  router.get('/v1/orgs/:org/users/:userId/effective', getEffective);
  router.get('/v1/orgs/:org/audit', listAudit);
}