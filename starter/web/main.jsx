import { createRoot } from 'react-dom/client';
import { useState, useEffect, useCallback } from 'react';

const THEME_COLORS = { cobalt: '#1c3d5a', slate: '#3a3f47', amber: '#7a4b12', forest: '#1f4d2b', crimson: '#5a1f28' };
function colorForTheme(theme) {
  if (THEME_COLORS[theme]) return THEME_COLORS[theme];
  let hash = 0;
  for (const ch of theme ?? 'default') hash = (hash * 31 + ch.charCodeAt(0)) % 360;
  return `hsl(${hash}, 45%, 30%)`;
}

let accessToken = null; // in memory only — never localStorage/sessionStorage

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(`/v1${path}`, {
    method, headers, credentials: 'include',
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const err = new Error(json?.error?.message ?? 'request failed');
    err.status = res.status;
    err.code = json?.error?.code;
    throw err;
  }
  return json;
}

const hasPerm = (permissions, key) => permissions?.[key]?.effect === 'allow';

function LoginScreen({ onLogin, error }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  return (
    <div data-testid="login-form">
      <input data-testid="login-email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
      <input data-testid="login-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
      <button data-testid="login-submit" onClick={() => onLogin(email, password)}>Log in</button>
      {error && <div data-testid="login-error">{error}</div>}
    </div>
  );
}

function DevicesView({ orgId }) {
  const [devices, setDevices] = useState(null);
  useEffect(() => { api(`/orgs/${orgId}/devices`).then((r) => setDevices(r.devices)); }, [orgId]);
  if (devices === null) return null;
  if (devices.length === 0) return <div data-testid="devices-empty">No devices yet.</div>;

  return (
    <table><tbody>
      {devices.map((d) => (
        <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
          <td>{d.name}</td>
          <td>
            {Object.keys(d.permissions)
              .filter((p) => p.startsWith('device:') && d.permissions[p].effect === 'allow')
              .map((p) => (
                <button key={p} data-permission={p} data-state="unlocked">{p.split(':')[1]}</button>
              ))}
          </td>
        </tr>
      ))}
    </tbody></table>
  );
}

function PeopleView({ orgId }) {
  const [members, setMembers] = useState(null);
  useEffect(() => { api(`/orgs/${orgId}/members`).then((r) => setMembers(r.members)); }, [orgId]);
  if (members === null) return null;
  return (
    <table><tbody>
      {members.map((m) => (
        <tr key={m.user_id} data-testid="user-row" data-user-id={m.user_id}>
          <td>{m.email}</td><td>{m.role}</td><td>{m.status}</td>
        </tr>
      ))}
    </tbody></table>
  );
}

function GrantsView({ orgId, permissions }) {
  const [grants, setGrants] = useState(null);
  const [showNew, setShowNew] = useState(false);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [form, setForm] = useState({ userId: '', deviceId: '', effect: 'allow', permissions: [] });

  const load = useCallback(() => { api(`/orgs/${orgId}/grants`).then((r) => setGrants(r.grants)); }, [orgId]);
  useEffect(load, [load]);

  const canCreate = hasPerm(permissions, 'grant:create');
  const canRevoke = hasPerm(permissions, 'grant:revoke');

  useEffect(() => {
    if (canCreate) {
      api(`/orgs/${orgId}/members`).then((r) => setMembers(r.members));
      api(`/orgs/${orgId}/devices`).then((r) => setDevices(r.devices));
    }
  }, [orgId, canCreate]);

  const togglePerm = (p) => setForm((f) => ({
    ...f, permissions: f.permissions.includes(p) ? f.permissions.filter((x) => x !== p) : [...f.permissions, p],
  }));

  const submit = async () => {
    await api(`/orgs/${orgId}/grants`, {
      method: 'POST',
      body: { userId: form.userId, deviceId: form.deviceId || null, effect: form.effect, permissions: form.permissions },
    });
    setShowNew(false);
    setForm({ userId: '', deviceId: '', effect: 'allow', permissions: [] });
    load();
  };

  const revoke = async (id) => { await api(`/orgs/${orgId}/grants/${id}`, { method: 'DELETE' }); load(); };

  if (grants === null) return null;

  return (
    <div>
      {canCreate && !showNew && <button data-testid="new-grant" onClick={() => setShowNew(true)}>New grant</button>}
      {showNew && (
        <div>
          <select data-testid="grant-user" value={form.userId} onChange={(e) => setForm((f) => ({ ...f, userId: e.target.value }))}>
            <option value="">select user</option>
            {members.map((m) => <option key={m.user_id} value={m.user_id}>{m.email}</option>)}
          </select>
          <select data-testid="grant-device" value={form.deviceId} onChange={(e) => setForm((f) => ({ ...f, deviceId: e.target.value }))}>
            <option value="">org-wide</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
          <select data-testid="grant-effect" value={form.effect} onChange={(e) => setForm((f) => ({ ...f, effect: e.target.value }))}>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
          {Object.keys(permissions).map((p) => (
            <label key={p}>
              <input type="checkbox" data-permission-key={p} checked={form.permissions.includes(p)} onChange={() => togglePerm(p)} />
              {p}
            </label>
          ))}
          <button data-testid="grant-submit" onClick={submit}>Create</button>
        </div>
      )}
      <table><tbody>
        {grants.map((g) => (
          <tr key={g.id} data-testid="grant-row" data-effect={g.effect}>
            <td>{g.user_id}</td><td>{g.device_id ?? 'org-wide'}</td><td>{g.effect}</td>
            {canRevoke && <td><button data-testid="revoke-grant" onClick={() => revoke(g.id)}>Revoke</button></td>}
          </tr>
        ))}
      </tbody></table>
    </div>
  );
}

function SessionsView({ orgId }) {
  const [sessions, setSessions] = useState(null);
  useEffect(() => { api(`/orgs/${orgId}/sessions`).then((r) => setSessions(r.sessions)); }, [orgId]);
  if (sessions === null) return null;
  return (
    <table><tbody>
      {sessions.map((s) => <tr key={s.id}><td>{s.device_id}</td><td>{s.mode}</td><td>{s.state}</td></tr>)}
    </tbody></table>
  );
}

function AuditView({ orgId }) {
  const [events, setEvents] = useState(null);
  useEffect(() => { api(`/orgs/${orgId}/audit?limit=100`).then((r) => setEvents(r.events)); }, [orgId]);
  if (events === null) return null;
  return (
    <table><tbody>
      {events.map((e) => <tr key={e.id}><td>{e.action}</td><td>{e.result}</td><td>{e.reason_code}</td></tr>)}
    </tbody></table>
  );
}

function AdminView({ orgId, permissions, onRefresh }) {
  const canRename = hasPerm(permissions, 'org:update');
  const canDelete = hasPerm(permissions, 'org:delete');
  return (
    <div>
      {canRename && (
        <button data-testid="rename-org" onClick={async () => {
          const name = window.prompt('New organization name');
          if (name) { await api(`/orgs/${orgId}`, { method: 'PATCH', body: { name } }); onRefresh(); }
        }}>Rename org</button>
      )}
      {canDelete && (
        <button data-testid="delete-org" onClick={async () => {
          if (window.confirm('Delete this organization?')) await api(`/orgs/${orgId}`, { method: 'DELETE' });
        }}>Delete org</button>
      )}
    </div>
  );
}

const NAV_ITEMS = [
  { key: 'devices', label: 'Devices', permission: 'device:list' },
  { key: 'people', label: 'People', permission: 'user:read' },
  { key: 'grants', label: 'Grants', permission: 'user:read' },
  { key: 'sessions', label: 'Sessions', permission: 'session:view' },
  { key: 'audit', label: 'Audit', permission: 'audit:read' },
];

function Shell({ session, nav, setNav, onSwitchOrg, onCreateOrg, onRefresh }) {
  const { orgId, role, orgs, permissions } = session;
  const theme = orgs.find((o) => o.id === orgId)?.theme;
  const showAdmin = hasPerm(permissions, 'org:update') || hasPerm(permissions, 'org:delete');

  return (
    <div data-testid="app-shell" data-org-id={orgId} data-org-theme={theme}
         style={{ background: colorForTheme(theme), minHeight: '100vh', color: '#fff' }}>
      <header>
        <span data-testid="active-role">{role}</span>
        <div>
          {orgs.map((o) => (
            <button key={o.id} data-testid="org-option" data-org-id={o.id} onClick={() => onSwitchOrg(o.id)}>{o.name}</button>
          ))}
          <button data-testid="create-org" onClick={onCreateOrg}>+ New org</button>
        </div>
      </header>
      <nav>
        {NAV_ITEMS.filter((n) => hasPerm(permissions, n.permission)).map((n) => (
          <button key={n.key} data-testid={`nav-${n.key}`} onClick={() => setNav(n.key)}>{n.label}</button>
        ))}
        {showAdmin && <button data-testid="nav-admin" onClick={() => setNav('admin')}>Admin</button>}
      </nav>
      <main>
        {nav === 'devices' && <DevicesView orgId={orgId} />}
        {nav === 'people' && <PeopleView orgId={orgId} />}
        {nav === 'grants' && <GrantsView orgId={orgId} permissions={permissions} />}
        {nav === 'sessions' && <SessionsView orgId={orgId} />}
        {nav === 'audit' && <AuditView orgId={orgId} />}
        {nav === 'admin' && <AdminView orgId={orgId} permissions={permissions} onRefresh={onRefresh} />}
      </main>
    </div>
  );
}

function InvitePage({ token, onDone }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    api(`/invites/${token}`).then(setInvite).catch(() => setError('This invite link is no longer valid.'));
  }, [token]);

  const submit = async () => {
    try {
      await api(`/invites/${token}/accept`, { method: 'POST', body: { name, password } });
      onDone();
    } catch (err) {
      setError(err.message);
    }
  };

  if (error) return <div data-testid="invite-error">{error}</div>;
  if (!invite) return null;

  return (
    <div>
      <div data-testid="invite-role">{invite.role}</div>
      <input data-testid="invite-email" value={invite.email} readOnly />
      <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} />
      <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button data-testid="invite-submit" onClick={submit}>Accept invite</button>
    </div>
  );
}

function App() {
  const [session, setSession] = useState(null);
  const [loginError, setLoginError] = useState(null);
  const [booting, setBooting] = useState(true);
  const [nav, setNav] = useState('devices');
  const [invitePath, setInvitePath] = useState(null);

  useEffect(() => {
    const m = window.location.pathname.match(/^\/invite\/(.+)$/);
    if (m) { setInvitePath(m[1]); setBooting(false); return; }

    (async () => {
      try {
        const r = await api('/auth/refresh', { method: 'POST' });
        accessToken = r.token;
        setSession(await api('/auth/me'));
      } catch { /* no valid session — show login */ }
      finally { setBooting(false); }
    })();
  }, []);

  const login = useCallback(async (email, password) => {
    setLoginError(null);
    if (!email || !password) { setLoginError('email and password are required'); return; }
    try {
      const r = await api('/auth/login', { method: 'POST', body: { email, password } });
      accessToken = r.token;
      setSession(r);
      setNav('devices');
    } catch (err) {
      setLoginError(err.message ?? 'invalid email or password');
    }
  }, []);

  const switchOrg = useCallback(async (orgId) => {
    const r = await api('/auth/token', { method: 'POST', body: { orgId } });
    accessToken = r.token;
    setSession(await api('/auth/me'));
    setNav('devices');
  }, []);

  const createOrg = useCallback(async () => {
    const name = window.prompt('Organization name');
    if (!name) return;
    const created = await api('/orgs', { method: 'POST', body: { name } });
    await switchOrg(created.id);
  }, [switchOrg]);

  if (booting) return null;
  if (invitePath) return <InvitePage token={invitePath} onDone={() => { window.location.href = '/'; }} />;
  if (!session) return <LoginScreen onLogin={login} error={loginError} />;

  return (
    <Shell
      session={session} nav={nav} setNav={setNav}
      onSwitchOrg={switchOrg} onCreateOrg={createOrg}
      onRefresh={async () => setSession(await api('/auth/me'))}
    />
  );
}

createRoot(document.getElementById('root')).render(<App />);