// Role vocabulary for OnMind-XID (RBAC levels).
//
// Roles are: admin | owner | user | guest, ranked by access level:
//   admin (3) > owner (2) > user (1) > guest (0)
//
// The *assignment* lives with the identity record, so there is no separate
// roles file:
//   - Local / container: optional `[role]` tag on the xusers.txt line
//     (`[owner] alice@example.com[:secret]`). Without a tag the user falls back
//     to XID_DEFAULT_ROLE (default: user).
//   - KV / DynamoDB: the `role` field inside the XID_USERS record.
//
// Reads/writes: getRole() / setRole() in users.js (same store as the identity).
// This module is a leaf (no imports) so users.js can validate tags without a
// circular dependency.

export const ROLES = ['admin', 'owner', 'user', 'guest']
export const ROLE_RANK = { admin: 3, owner: 2, user: 1, guest: 0 }

export function isValidRole(role) {
  return ROLES.includes(String(role || '').trim().toLowerCase())
}

export function defaultRole(env) {
  const configured = env?.XID_DEFAULT_ROLE || process.env.XID_DEFAULT_ROLE
  return isValidRole(configured) ? String(configured).trim().toLowerCase() : 'user'
}
