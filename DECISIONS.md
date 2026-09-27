## Why exp uses <= not <

Considered: exp < now

Chose: exp <= now

I used <= because if exp is exactly the same as now, the token has already reached its expiry time. With just <, it could still pass for that exact moment. It is a very small edge case, but there is no real reason to allow it. So <= makes the expiry check stricter.

---

## Why owner bypasses the equal-rank modification rule

Considered: use the "cannot modify equal or higher rank" rule for owners also.

Chose: owner can modify another owner.

The reason is that there can be more than one owner in an organization. For example, Acme already has multiple owners in the fixture.

If owners could not modify another owner because they have the same rank, then they could not change each other's roles. The only other option would be changing your own role, but self-role changes are already blocked.

That could leave the organization with no way to change an owner's role. Since owner is already the highest rank, allowing one owner to modify another owner does not let them go above owner. It is mainly needed so owners can manage other owners.

---

## Why org-level and device-level permission resolution use different queries

Considered: always filter grants by the requested `device_id`.

Chose: handle org-level and device-level checks differently.

For an org-level check, I include grants from any device. This is because the org-level view needs to know if the user has the permission anywhere in the organization.

For a specific device, I only use the org-wide grants (device_id = null) and grants for that exact device.

This is important because a permission given for device A should not make the same permission appear on device B.

---

## Why the grants UI gets permission keys from resolve()

Considered: use a fixed list of the 19 permissions from the documentation.

Chose: use Object.keys(session.permissions) from resolve().

The reason is the personalisation data can contain a permission that is not in the documented 19 permissions. In my fixture there is an extra device:reboot permission.

If I used a hardcoded list, that permission would not appear in the grants UI, so it could not be selected there.

Using the permissions returned by the server means the UI uses the actual permissions instead of assuming that the documented list is always the complete list.
