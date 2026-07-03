import { describe, it, expect } from "vitest";
import { isValidIpOrCidr, isUnsafeTarget } from "../src/validate.js";

describe("isValidIpOrCidr", () => {
  it.each(["1.2.3.4", "203.0.113.9", "198.51.100.0/24", "::1", "2001:db8::1",
           "2001:db8::/48", "::ffff:192.0.2.1", "0:0:0:0:0:ffff:192.0.2.1",
           "2400:cb00::/32", "1.2.3.4/0", "::/0"])(
    "accepts %s", (s) => expect(isValidIpOrCidr(s)).toBe(true));
  it.each(["999.999.999.999", "256.0.0.1", "1.2.3", "deadbeef", "::::",
           "1.2.3.4/33", "2001:db8::/129", "", "1.2.3.4 ", "evil\"x", "1.2.3.4/1/2",
           "1.2.3.4/00", "1.2.3.4/03", "2001:db8::/033", "1:2:3:4:5:6:7:8:9"])(
    "rejects %s", (s) => expect(isValidIpOrCidr(s)).toBe(false));
});

describe("isUnsafeTarget", () => {
  it.each(["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "0.0.0.0/0", "1.2.3.4/0", "::/0"])(
    "flags %s", (s) => expect(isUnsafeTarget(s)).toBe(true));
  it.each(["1.2.3.4", "2001:db8::1", "198.51.100.0/24"])(
    "allows %s", (s) => expect(isUnsafeTarget(s)).toBe(false));
});
