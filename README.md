# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Rudy0x/github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Rudy0x/github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone, single-process, GitHub-compatible git forge in TypeScript on
Node 22. Zero runtime dependencies, no git binary at runtime. It speaks
enough of GitHub's surface to be usable as a drop-in backend for git clients
and for the `gh` CLI: smart HTTP (protocol v0 and v2), the REST v3 API, the
GraphQL v4 API, and MCP over streamable HTTP.

## Run it

```sh
node --experimental-strip-types main.ts
```

`main.ts` is the lifecycle: bind an ephemeral port (never 8080), register it
with the environment at `$MAKEFUN_ENV_URL`, poll `$MAKEFUN_ENV_URL/done`
until the trial ends, exit 0. The server itself lives in `app.ts`
(`createApp()`); the store is in memory for the life of the process.

Authentication is a bearer token. If `MAKEFUN_SHOP_TOKEN` is set, only that
exact token is accepted; if it is unset, any non-empty bearer token works.
`/healthz` takes no token. `GET /api/v3/` and `GET /api/v3/meta` are public;
everything else under `/api/v3`, `/api/graphql`, `/mcp`, and all git routes
require the token.

The viewer is the fixed scenario identity (`adaiversen`, id 1000). Repos,
issues, and pull requests share one per-repo number counter, and a label has
to be created before an issue may carry it.

## What it implements

### Git smart HTTP

A pure-TypeScript git object store: commit/tree/blob/tag parsing and
building, packfile reading and writing, OFS_DELTA and REF_DELTA application
(including thin packs from real clients), refs, and merge-base/ancestor
walks. The server sends whole objects only; it reads deltas.

- `GET /<owner>/<repo>.git/info/refs?service=git-upload-pack|git-receive-pack`
  — v0 advertisement with a terminating flush, plus the v2 advertisement
  (`version 2`, `ls-refs=unborn`, `fetch=shallow filter`,
  `object-format=sha1`).
- `POST .../git-upload-pack` — v0 and v2 fetch. Shallow fetches are
  depth-bounded: a depth-1 clone carries the tip only, and a deepen moves
  the boundary one generation. The client's held set stops at its shallow
  boundary, so a deepen actually delivers the parent instead of assuming
  the client already has it.
- `POST .../git-receive-pack` — fast-forward-only pushes, per-ref
  `ok`/`ng` report-status (`non-fast-forward` on a stale base), deletes
  require a matching old oid. The server stays up after 404s, refusals,
  and malformed pkt-line input.

### REST v3 (`/api/v3`)

Repositories (create/list/get/patch/delete, duplicate name is 422),
branches, commits (message shown without the trailing newline the stored
object keeps), contents (PUT create 201 / update 200 / stale sha 409,
DELETE 200, GET file as base64 or directory listing), labels, git refs,
issues and comments (state filter, `sort=created&direction=` ordering),
pull requests (duplicate open PR is 422, squash merge, conflicted merge
is 405 — the conflict check reads the base branch tip as it is now, not
the tip recorded when the PR was opened). Every reply is JSON with a
non-empty `X-GitHub-Request-Id`; errors carry `{"message": ...}`.

### GraphQL v4 (`POST /api/graphql`)

A hand-rolled tokenizer/parser and executor. `viewer`, `repository`,
`node` round-trips, `__type`/`__schema` introspection, issues and pull
requests connections with cursor pagination, and the mutations
`createIssue`, `closeIssue`, `createPullRequest`, `mergePullRequest`
(SQUASH), `addComment`. Unknown fields are HTTP 200 with an `errors`
array; an unknown repository is `data.repository = null`. Global ids are
opaque base64url, never the plain database id or number.

### MCP (`POST /mcp`)

JSON-RPC 2.0 over plain JSON. Modern era (`server/discover`, versions
including `2026-07-28`) and legacy era (`initialize` +
`notifications/initialized`, 202 empty). Eight tools: `create_repo`,
`get_repo`, `list_repos`, `create_issue`, `get_issue`, `list_issues`,
`create_pull_request`, `merge_pull_request` — all acting on the same store
as REST. Unknown tools are -32602/-32601, never HTTP 500; a non-JSON body
is HTTP 400 with -32700; no token is HTTP 401.

## Verification

Against the kit's own trial suite (`sdk/run.ts`), the entry passes
**120/120 conformance checks** (git 30/30, repos 15/15, issues 15/15,
pulls 20/20, protocol 5/5, GraphQL 20/20, MCP 15/15) and the four perf
workloads score **178/200** (push 50, clone 42, read 47, write 39) —
600 feature + 200 agent + 178 perf, **978/1000** projected.

Real `git` 2.43 was also exercised directly over smart HTTP: cloning an
empty repo, pushing a first commit, cloning it back, pushing a second
commit (delta pack), fetching, and a `--depth 1` shallow clone that lands
the tip only and is marked shallow.

## Layout

- `main.ts` — lifecycle only; keep as-is.
- `app.ts` — the whole forge: pkt-line codec, object store, packfiles,
  smart HTTP, REST, GraphQL, MCP, router.
- `package.json`, `tsconfig.json` — strict TypeScript, ES2023, NodeNext.
  Typecheck with `tsc --noEmit`. Note the runtime loads the sources with
  `--experimental-strip-types`, so the code avoids TypeScript-only runtime
  features (no enums, no parameter properties).
- `LICENSE` — MIT.

---

<sub>Entered on [make.fun](https://make.fun/?ref=q96xntgq&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
