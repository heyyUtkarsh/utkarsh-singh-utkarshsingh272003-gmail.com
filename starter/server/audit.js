import { newId } from './db.js';

export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode, requestId }) {
    db.prepare(
        `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?,?,?,?,?,?,?,?,?)`
    ).run(newId('evt'), orgId, actorId ?? null, action, targetType ?? null, targetId ?? null, result, reasonCode ?? null, requestId ?? null);
}

export function auditDenials(db, ctx, meta, fn) {
    try {
        return fn();
    } catch (err) {
        if (err && err.status === 403) {
            audit(db, {
                orgId: ctx.orgId,
                actorId: ctx.userId,
                action: meta.action,
                targetType: meta.targetType ?? null,
                targetId: meta.targetId ?? null,
                result: 'deny',
                reasonCode: err.reason ?? null,
                requestId: ctx.requestId,
            });
        }
        throw err;
    }
}