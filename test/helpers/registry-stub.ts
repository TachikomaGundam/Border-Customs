// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 13
//
// Loopback registry stub for the pre-flight suites: a real `node:http` server
// on an EPHEMERAL port (port 0 ⇒ OS-assigned, so concurrent suite runs and
// sibling worktrees never collide). Zero public-network I/O — plan todo 13
// pins "no real network in the suite". Routes are a small script: each entry
// matches pathname prefix, answers with status + JSON body (or raw text).
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export type StubRoute = {
  /** Matched against the URL pathname (exact or prefix with `startsWith`). */
  readonly path: string;
  readonly prefix?: boolean;
  /** Status to answer; default 200. */
  readonly status?: number;
  /** JSON body (mutually exclusive with `raw`). */
  readonly body?: unknown;
  /** Raw body text — for the malformed-JSON scenarios. */
  readonly raw?: string;
  /** Extra response headers. */
  readonly headers?: Readonly<Record<string, string>>;
};

export type RegistryStub = {
  readonly port: number;
  /** `http://127.0.0.1:<port>` — drop-in for targets.npm.registry / targets.pypi.repository. */
  readonly url: string;
  /** Pathnames requested so far (probe-count assertions, never empty by accident). */
  readonly hits: readonly string[];
  /** Fail-closed test mode: accept the socket but NEVER answer (hang-then-timeout). */
  close(): Promise<void>;
};

export async function startRegistryStub(routes: readonly StubRoute[]): Promise<RegistryStub> {
  const hits: string[] = [];
  const sockets: import("node:net").Socket[] = [];
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (res.socket !== null) sockets.push(res.socket);
    const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    hits.push(path);
    const route =
      routes.find((r) => (r.prefix === true ? path.startsWith(r.path) : path === r.path)) ??
      routes.find((r) => r.prefix === true && r.path === "*");
    if (route === undefined) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }
    const status = route.status ?? 200;
    if (route.raw !== undefined) {
      res.writeHead(status, { "content-type": "application/json", ...route.headers });
      res.end(route.raw);
      return;
    }
    res.writeHead(status, { "content-type": "application/json", ...route.headers });
    res.end(JSON.stringify(route.body ?? {}));
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("stub server failed to bind an ephemeral port");
  return {
    port: addr.port,
    url: `http://127.0.0.1:${String(addr.port)}`,
    hits,
    // npm fetches with keep-alive; server.close() alone would wait for idle
    // sockets forever — destroy them first (verified empirically: the first
    // characterization run hung 240s on exactly this).
    close: () =>
      new Promise<void>((ok, err) => {
        for (const s of sockets) s.destroy();
        server.close((e) => (e === undefined ? ok() : err(e)));
      }),
  };
}

/**
 * A port that WAS bound and is now closed: connecting gets ECONNREFUSED
 * deterministically. (A blind offset like stub.port+5000 can collide with
 * another concurrent test file's ephemeral listener — observed once under
 * full-suite load.)
 */
export async function closedEphemeralPort(): Promise<number> {
  const srv = createServer(() => {
    /* unused */
  });
  await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok));
  const addr = srv.address();
  if (addr === null || typeof addr === "string") throw new Error("closed-port probe failed to bind");
  const port = addr.port;
  await new Promise<void>((ok) => srv.close(() => ok()));
  return port;
}

/** A server that accepts connections and says nothing forever — the hung-registry probe. */
export async function startHangingStub(): Promise<RegistryStub> {
  const sockets: import("node:net").Socket[] = [];
  const server = createServer(() => {
    /* never answer */
  });
  server.on("connection", (s) => sockets.push(s));
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("hanging stub failed to bind");
  return {
    port: addr.port,
    url: `http://127.0.0.1:${String(addr.port)}`,
    hits: [],
    close: () =>
      new Promise<void>((ok, err) => {
        for (const s of sockets) s.destroy();
        server.close((e) => (e === undefined ? ok() : err(e)));
      }),
  };
}

export const PACKUMENT_WIDGETS_100 = {
  name: "widgets",
  "dist-tags": { latest: "1.0.0" },
  versions: {
    "1.0.0": {
      name: "widgets",
      version: "1.0.0",
      _npmUser: { name: "alice", email: "alice@self.example" },
    },
  },
  maintainers: [{ name: "alice", email: "alice@self.example" }],
  repository: { url: "git+https://origin.example/widgets.git" },
};
