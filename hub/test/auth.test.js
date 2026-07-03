import { describe, it, expect } from "vitest";
import { checkAuth } from "../src/auth.js";
const req = (h) => new Request("https://hub/x", { headers: h ? { authorization: h } : {} });

describe("checkAuth", () => {
  it("accepts exact", () => expect(checkAuth(req("Bearer sekret"), "sekret")).toBe(true));
  it("rejects wrong", () => expect(checkAuth(req("Bearer nope"), "sekret")).toBe(false));
  it("rejects missing", () => expect(checkAuth(req(null), "sekret")).toBe(false));
  it("rejects non-bearer", () => expect(checkAuth(req("Basic sekret"), "sekret")).toBe(false));
  it("rejects empty expected", () => expect(checkAuth(req("Bearer x"), "")).toBe(false));
});
