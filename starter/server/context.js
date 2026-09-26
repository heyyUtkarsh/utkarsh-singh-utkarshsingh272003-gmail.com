import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
    return function buildContext(req, params) {
        const header = req.headers['authorization'] ?? '';
        const [scheme, token] = header.split(' ');
        if (scheme !== 'Bearer' || !token) {
            throw unauthenticated('missing bearer token');
        }

        const claims = verifyAccessToken(token, secret);

        const membership = db
            .prepare(
                `SELECT m.* FROM memberships m
         JOIN organizations o ON o.id = m.org_id
         WHERE m.org_id = ? AND m.user_id = ? AND o.deleted_at IS NULL`
            )
            .get(claims.org, claims.sub);

        // Missing membership (or a deleted org) is treated as "no membership" —
        // assertFresh throws unauthenticated for that case.
        assertFresh(claims, membership ?? null);

        // The token's org claim is the only org this caller may address. A path
        // naming a different org is invisible, not forbidden.
        if (params.org && params.org !== claims.org) {
            throw notFound();
        }

        return {
            userId: claims.sub,
            orgId: claims.org,
            role: membership.role,
            membership,
            claims,
        };
    };
}