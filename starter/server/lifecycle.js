import { badRequest, forbidden, lastOwner } from './http.js';
import { nowIso } from './db.js';
import { resolve } from './permissions.js';

export function roleRanks(db) {
    const rows = db.prepare('SELECT key, rank FROM roles').all();
    const ranks = {};
    for (const r of rows) ranks[r.key] = r.rank;
    return ranks;
}

export function assertRoleExists(db, role) {
    const row = db.prepare('SELECT 1 FROM roles WHERE key = ?').get(role);
    if (!row) throw badRequest(`unknown role: ${role}`);
}

// Modification authority ONLY — never used to answer a can() question.
// Owner is the top of the ladder and may modify anyone, including another
// owner; everyone else may only modify someone strictly below them.
export function assertCanModify(db, callerRole, targetRole) {
    if (callerRole === 'owner') return;
    const ranks = roleRanks(db);
    if (ranks[callerRole] === undefined || ranks[targetRole] === undefined || ranks[callerRole] <= ranks[targetRole]) {
        throw forbidden('cannot modify a user of equal or higher rank', 'insufficient_rank');
    }
}

export function assertNotLastOwner(db, orgId, userId) {
    const owners = db
        .prepare("SELECT user_id FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'")
        .all(orgId);
    if (owners.length === 1 && owners[0].user_id === userId) throw lastOwner();
}

export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
    const conditions = ['org_id = ?', "state = 'active'"];
    const p = [orgId];
    if (userId) { conditions.push('user_id = ?');
        p.push(userId); }
    if (deviceId) { conditions.push('device_id = ?');
        p.push(deviceId); }
    if (exceptSessionId) { conditions.push('id != ?');
        p.push(exceptSessionId); }
    db.prepare(`UPDATE sessions SET state='ended', end_reason=?, ended_at=? WHERE ${conditions.join(' AND ')}`)
        .run(reason, nowIso(), ...p);
}

export function snapshotAuthority(db, { userId, orgId, deviceId }) {
    const { role, permissions } = resolve(db, { userId, orgId, deviceId });
    return { role, permissions };
}

export function sessionExpiry(db, orgId, startedAt = new Date()) {
    const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
    const minutes = org ?.max_session_minutes ?? 60;
    return new Date(startedAt.getTime() + minutes * 60000).toISOString();
}