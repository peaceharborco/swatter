export function checkAuth(request, expectedToken) {
  if (!expectedToken) return false;
  const m = (request.headers.get("authorization") || "").match(/^Bearer (.+)$/);
  if (!m) return false;
  const got = m[1];
  if (got.length !== expectedToken.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expectedToken.charCodeAt(i);
  return diff === 0;
}
