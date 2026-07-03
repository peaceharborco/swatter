function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...headers } });
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return json({ ok: true });
    return new Response("not found", { status: 404 });
  },
  async scheduled(event, env, ctx) { /* prune wired in Task 9 */ },
};
