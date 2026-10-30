// Vendored from peaceharbor/toolbox/coastguard (canonical). Do not edit in a
// Worker repo: change the toolbox, then re-vendor. tests/coastguard/check.sh
// fails a copy that differs.
//
// The CoastGuard halt guard (SPEC.md "Halt"). When the secret COASTGUARD_HALT
// is set on a Worker, every way that Worker can start running does no work:
//
//   fetch              503 + Retry-After, nothing else runs
//   scheduled, tail    return
//   queue              retryAll after 12 h: messages are kept, not processed
//   email              rejected
//   Durable Object     fetch 503; alarm returns WITHOUT rescheduling (this is
//                      what ends an alarm loop); a WebSocket message closes it;
//                      webSocketClose / webSocketError do nothing
//
// phcloudflare sets the secret through the Workers secrets API, which deploys
// the same code and bindings at once; deleting it restores the Worker. A later
// `wrangler deploy` keeps it, so a deploy cannot quietly undo a halt.
//
// Use:
//   export default guardWorker({ fetch, scheduled, queue });
//   class RoomBase extends DurableObject { ... }
//   export const Room = guardDurableObject(RoomBase);

export const HALT_SECRET = "COASTGUARD_HALT";

/** 12 hours, the longest delay Queues accepts. */
export const QUEUE_RETRY_DELAY_SECONDS = 43200;

export function halted(env: unknown): boolean {
  const v = (env as Record<string, unknown> | null | undefined)?.[HALT_SECRET];
  return typeof v === "string" && v.length > 0;
}

export function haltedResponse(): Response {
  return new Response("Temporarily unavailable.", {
    status: 503,
    headers: { "retry-after": "3600", "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" },
  });
}

// The handler names a Worker may export. Anything else is refused when the
// module loads, so a new kind of handler gets a decision here instead of
// slipping past the guard.
const PASS = new Set(["scheduled", "tail", "trace"]);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Fn = (...args: any[]) => any;

export function guardWorker<T extends object>(handlers: T): T {
  const h = handlers as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(h)) {
    if (typeof value !== "function") {
      out[name] = value;
      continue;
    }
    const fn = value as Fn;
    if (name === "fetch") {
      out.fetch = (req: Request, env: unknown, ctx: unknown) =>
        halted(env) ? haltedResponse() : fn.call(h, req, env, ctx);
    } else if (name === "queue") {
      out.queue = (batch: { retryAll(o?: { delaySeconds?: number }): void }, env: unknown, ctx: unknown) => {
        if (halted(env)) {
          batch.retryAll({ delaySeconds: QUEUE_RETRY_DELAY_SECONDS });
          return;
        }
        return fn.call(h, batch, env, ctx);
      };
    } else if (name === "email") {
      out.email = (message: { setReject(reason: string): void }, env: unknown, ctx: unknown) => {
        if (halted(env)) {
          message.setReject("Temporarily unavailable.");
          return;
        }
        return fn.call(h, message, env, ctx);
      };
    } else if (PASS.has(name)) {
      out[name] = (event: unknown, env: unknown, ctx: unknown) => (halted(env) ? undefined : fn.call(h, event, env, ctx));
    } else {
      throw new Error(`coastguard: no halt rule for handler "${name}"; add one to the toolbox`);
    }
  }
  return out as T;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type DOClass = abstract new (...args: any[]) => any;

/** Thrown by a guarded Durable Object's RPC methods while halted. */
export class HaltedError extends Error {
  constructor() {
    super("coastguard: halted");
  }
}

// Lifecycle methods with their own halted behaviour; every other method a
// class defines (its RPC surface and its helpers) throws HaltedError.
const DO_SPECIAL = new Set(["constructor", "fetch", "alarm", "webSocketMessage", "webSocketClose", "webSocketError"]);

// The platform's base classes: their methods are not ours to wrap. Matched by
// name, and Container also by a method only it defines, because a bundler can
// rename a class that comes from npm (cloudflare:workers stays external).
function isPlatformBase(p: object): "do" | "container" | false {
  const name = (p as { constructor?: { name?: string } }).constructor?.name;
  if (name === "Container" || Object.prototype.hasOwnProperty.call(p, "startAndWaitForPorts")) return "container";
  if (name === "DurableObject" || name === "DurableObjectBase") return "do";
  return false;
}

/** Wraps a Durable Object class. The env is read from `this.env`, which the
 *  `DurableObject` base class (and `Container`, which extends it) sets.
 *  Covers the methods of `Base` and of every user class between it and the
 *  platform base: `fetch` answers 503, `alarm` returns without doing anything
 *  (so it is not rescheduled), a WebSocket message closes the socket, and any
 *  other method (RPC) throws HaltedError. */
export function guardDurableObject<C extends DOClass>(Base: C): C {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore: a mixin over an abstract constructor
  class Guarded extends Base {}
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proto = Guarded.prototype as any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const isHalted = (self: any) => halted(self?.env);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const has = (name: string) => typeof (Base.prototype as any)[name] === "function";
  if (has("fetch")) {
    const own = Base.prototype.fetch as Fn;
    proto.fetch = function (this: unknown, ...args: unknown[]) {
      return isHalted(this) ? haltedResponse() : own.apply(this, args);
    };
  }
  // A Container's own alarm is what stops it, so a halted container is told
  // to stop instead (instance time is a meter too).
  let container = false;
  for (let p = Base.prototype; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
    if (isPlatformBase(p) === "container") container = true;
  }
  if (has("alarm")) {
    const own = Base.prototype.alarm as Fn;
    proto.alarm = async function (this: { stop?: () => Promise<unknown> }, ...args: unknown[]) {
      if (!isHalted(this)) return own.apply(this, args);
      if (container && typeof this.stop === "function") {
        try {
          await this.stop();
        } catch {
          // Stopping is best effort; the alarm still does nothing else.
        }
      }
      return undefined;
    };
  }
  if (has("webSocketMessage")) {
    const own = Base.prototype.webSocketMessage as Fn;
    proto.webSocketMessage = function (this: unknown, ws: { close(code?: number, reason?: string): void }, ...rest: unknown[]) {
      if (isHalted(this)) {
        ws.close(1013, "Temporarily unavailable");
        return undefined;
      }
      return own.call(this, ws, ...rest);
    };
  }

  // A halted socket teardown does no work (no storage writes, no broadcast).
  for (const name of ["webSocketClose", "webSocketError"]) {
    if (!has(name)) continue;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const own = (Base.prototype as any)[name] as Fn;
    proto[name] = function (this: unknown, ...args: unknown[]) {
      return isHalted(this) ? undefined : own.apply(this, args);
    };
  }

  // Walk the user-defined chain (stop at the platform's DurableObject or
  // Container base, whose methods are not ours to wrap).
  const seen = new Set<string>();
  for (let p = Base.prototype; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
    if (isPlatformBase(p)) break;
    for (const name of Object.getOwnPropertyNames(p)) {
      if (DO_SPECIAL.has(name) || seen.has(name)) continue;
      seen.add(name);
      const d = Object.getOwnPropertyDescriptor(p, name);
      if (!d || typeof d.value !== "function") continue;
      const own = d.value as Fn;
      // An async method rejects, a plain one throws: the caller sees the same
      // shape of failure it would from the method itself.
      const isAsync = own.constructor?.name === "AsyncFunction";
      Object.defineProperty(proto, name, {
        ...d,
        value: function (this: unknown, ...args: unknown[]) {
          if (isHalted(this)) {
            if (isAsync) return Promise.reject(new HaltedError());
            throw new HaltedError();
          }
          return own.apply(this, args);
        },
      });
    }
  }
  Object.defineProperty(Guarded, "name", { value: Base.name });
  return Guarded as unknown as C;
}
