import { forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

function allPermissionKeys(db) {
    return db.prepare('SELECT key FROM permissions').all().map((r) => r.key);
}

function matchesPattern(permission, pattern) {
    if (pattern === '*') return true;
    if (pattern === permission) return true;
    if (pattern.endsWith(':*')) return permission.startsWith(pattern.slice(0, -1));
    return false;
}

function expandPattern(db, pattern) {
    if (pattern === '*') return allPermissionKeys(db);
    if (pattern.endsWith(':*')) {
        const prefix = pattern.slice(0, -1);
        return allPermissionKeys(db).filter((k) => k.startsWith(prefix));
    }
    return [pattern];
}

function loadGrants(db, orgId, userId, now) {
    const nowIso = now.toISOString();
    return db
        .prepare(
            `SELECT g.*, GROUP_CONCAT(gp.permission) AS patterns
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
       WHERE g.org_id = ? AND g.user_id = ? AND g.revoked_at IS NULL
         AND (g.starts_at IS NULL OR g.starts_at <= ?)
         AND (g.expires_at IS NULL OR g.expires_at > ?)
       GROUP BY g.id`
        )
        .all(orgId, userId, nowIso, nowIso);
}

function decideOne(db, membership, grants, permission, deviceId) {
    if (!membership) return { effect: 'deny', source: null, reason: 'not_a_member' };
    if (membership.status !== 'active') return { effect: 'deny', source: null, reason: 'suspended' };

    const relevant = grants.filter(
        (g) => g.device_id === null || deviceId === null || g.device_id === deviceId
    );
    const matches = (g) => g.patterns.split(',').some((pat) => matchesPattern(permission, pat));

    const deny = relevant.find((g) => g.effect === 'deny' && matches(g));
    if (deny) return { effect: 'deny', source: `grant:${deny.id}`, reason: 'explicit_deny' };

    const allow = relevant.find((g) => g.effect === 'allow' && matches(g));
    if (allow) return { effect: 'allow', source: `grant:${allow.id}`, reason: null };

    const baseline = db
        .prepare('SELECT 1 FROM role_permissions WHERE role = ? AND permission = ?')
        .get(membership.role, permission);
    if (baseline) return { effect: 'allow', source: `role:${membership.role}`, reason: null };

    return { effect: 'deny', source: null, reason: 'implicit' };
}

export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
    const membership = db
        .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
        .get(orgId, userId);
    const grants = membership ? loadGrants(db, orgId, userId, now) : [];

    const permissions = {};
    for (const key of allPermissionKeys(db)) {
        permissions[key] = decideOne(db, membership, grants, key, deviceId);
    }

    return { role: membership ?.role ?? null, permissions };
}

export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
    const { role } = resolve(db, { userId, orgId, now });
    const byDevice = {};
    for (const deviceId of deviceIds) {
        byDevice[deviceId] = resolve(db, { userId, orgId, deviceId, now }).permissions;
    }
    return { role, byDevice };
}

export function can(db, ctx, permission, deviceId) {
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
    return permissions[permission] ?.effect === 'allow';
}

export function assertCan(db, ctx, permission, deviceId) {
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
    const decision = permissions[permission];
    if (decision ?.effect !== 'allow') {
        throw forbidden('missing permission', decision ?.reason ?? 'missing_permission');
    }
}

export function assertMayGrant(db, ctx, patterns, deviceId = null) {
    for (const pattern of patterns) {
        for (const permission of expandPattern(db, pattern)) {
            if (!can(db, ctx, permission, deviceId)) {
                throw forbidden('cannot grant a permission you do not hold', 'missing_permission');
            }
        }
    }
}

export function assertCanStartSession(db, ctx, mode, deviceId) {
    if (!can(db, ctx, 'session:start', deviceId)) {
        throw forbidden('cannot start sessions', 'missing_permission');
    }
    if (!can(db, ctx, MODE_PERMISSION[mode], deviceId)) {
        throw forbidden(`cannot ${mode} this device`, 'missing_device_permission');
    }
}