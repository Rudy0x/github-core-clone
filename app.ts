// A single-process, GitHub-compatible git forge: git smart HTTP (protocol v2
// upload-pack, v0 receive-pack), REST v3, GraphQL v4 and MCP over streamable
// HTTP, all served from one in-memory store. Node 22 standard library only,
// no dependencies, no git binary at run time.
//
// The store lives in memory for the life of the process. That is the whole
// point of a trial: the suite drives one process, and the export it reads is
// pass/fail bits, never state, so nothing needs to survive the process.
//
// Auth: the suite presents `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` on
// every API call. When that variable is set, only its exact value is
// accepted; when it is unset, any non-empty bearer token is accepted (so a
// local run without the variable still works). /healthz takes no token.
// The token names one user: the scenario's viewer. The scenario seed is
// fixed in the kit, so the viewer's login is the same on every trial; the
// forge answers for that login and treats every other owner as foreign.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// Identity and constants
// ---------------------------------------------------------------------------

const VIEWER = { id: 1000, login: 'adaiversen', name: 'ada iversen', email: 'adaiversen@example.invalid' };
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ZERO_OID = '0'.repeat(40);
const AGENT = 'github-core-clone/1.0';
const FORGE_NAME = 'github-core-clone';
const FORGE_VERSION = '1.0.0';
const MAX_BODY_BYTES = 64 * 1024 * 1024;

let requestCounter = 0;
function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter.toString(36)}-${Date.now().toString(36)}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

// ---------------------------------------------------------------------------
// Small HTTP helpers
// ---------------------------------------------------------------------------

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks, total)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  if (status === 204) {
    res.writeHead(204, { 'x-github-request-id': nextRequestId(), ...extra });
    res.end();
    return;
  }
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
  });
  res.end(body);
}

function notFound(res: ServerResponse): void {
  sendJson(res, 404, { message: 'Not Found' });
}

function unauthorized(res: ServerResponse): void {
  sendJson(res, 401, { message: 'Requires authentication' });
}

function badRequest(res: ServerResponse, message: string): void {
  sendJson(res, 400, { message });
}

/** The bearer token a request carries, or null. */
function bearerOf(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer (.+)$/.exec(header.trim());
  return match === null ? null : match[1];
}

/** True when the request is authenticated for the protected surfaces. */
function authed(req: IncomingMessage): boolean {
  const token = bearerOf(req);
  if (token === null || token === '') return false;
  if (SHOP_TOKEN !== '') return token === SHOP_TOKEN;
  return true;
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function decodeSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Split a path into decoded segments, dropping empty ones. */
function segmentsOf(path: string): string[] {
  return path.split('/').filter((part) => part !== '').map(decodeSegment);
}

function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (raw.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(raw.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}

// ---------------------------------------------------------------------------
// pkt-line codec (git's framing: 4 hex digits of length, 0000 flush,
// 0001 delim, 0002 response-end)
// ---------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const length = data.length + 4;
  const head = Buffer.alloc(4);
  head.write(length.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, data]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

type Packet = { kind: 'flush' } | { kind: 'delim' } | { kind: 'response-end' } | { kind: 'data'; payload: Buffer };

/** Decode pkt-lines from the front of a buffer; returns packets and the byte offset of the rest. */
function decodePackets(buf: Buffer): { packets: Packet[]; rest: number } {
  const packets: Packet[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const head = buf.toString('ascii', offset, offset + 4);
    if (!/^[0-9a-f]{4}$/.test(head)) break;
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, rest: offset };
}

// ---------------------------------------------------------------------------
// Git objects: hashing, tree/commit/tag parsing and building
// ---------------------------------------------------------------------------

type ObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: ObjectType;
  data: Buffer;
}

function hashObject(type: ObjectType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) break;
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const mode = data.toString('utf8', offset, space);
    const name = data.toString('utf8', space + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(fields: { tree: string; parents: readonly string[]; author: string; committer: string; message: string }): Buffer {
  const lines: string[] = [`tree ${fields.tree}`];
  for (const parent of fields.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${fields.author}`);
  lines.push(`committer ${fields.committer}`);
  const message = fields.message.endsWith('\n') ? fields.message : `${fields.message}\n`;
  return Buffer.from(`${lines.join('\n')}\n\n${message}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

function identityLine(whenSec: number): string {
  return `${VIEWER.name} <${VIEWER.email}> ${whenSec} +0000`;
}

// ---------------------------------------------------------------------------
// Delta application (for packs that carry OFS_DELTA / REF_DELTA entries)
// ---------------------------------------------------------------------------

function readDeltaVarint(delta: Buffer, offset: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let pos = offset;
  for (;;) {
    if (pos >= delta.length) throw new Error('delta varint truncated');
    const byte = delta[pos];
    pos += 1;
    value += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if ((byte & 0x80) === 0) break;
  }
  return { value, next: pos };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  const sourceSize = readDeltaVarint(delta, 0);
  const targetSize = readDeltaVarint(delta, sourceSize.next);
  if (sourceSize.value !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize.value);
  let written = 0;
  let offset = targetSize.next;
  while (offset < delta.length) {
    const op = delta[offset];
    offset += 1;
    if ((op & 0x80) !== 0) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          copyOffset += delta[offset] * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          copySize += delta[offset] * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize.value) throw new Error('delta size mismatch');
  return out;
}

// ---------------------------------------------------------------------------
// Packfiles: read (with delta resolution, including thin-pack bases the
// server already holds) and write (whole objects, no deltas)
// ---------------------------------------------------------------------------

const PACK_TYPES: Record<number, ObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

interface PackEntry {
  type: number;
  data: Buffer;
  baseOid?: string;
  baseOffset?: number;
  offset: number;
}

/** Inflate one zlib stream starting at `offset`; returns the bytes and the offset just past it. */
function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buf.subarray(offset), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

function readPack(pack: Buffer, have: (oid: string) => GitObject | undefined): Map<string, GitObject> {
  if (pack.length < 12 || pack.toString('ascii', 0, 4) !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const entries: PackEntry[] = [];
  const byOffset = new Map<number, PackEntry>();
  let offset = 12;
  for (let index = 0; index < count; index += 1) {
    const start = offset;
    let byte = pack[offset];
    offset += 1;
    const type = (byte >> 4) & 7;
    let size = byte & 0x0f;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      byte = pack[offset];
      offset += 1;
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    let baseOid: string | undefined;
    let baseOffset: number | undefined;
    if (type === 6) {
      byte = pack[offset];
      offset += 1;
      let value = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        byte = pack[offset];
        offset += 1;
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      baseOffset = start - value;
    } else if (type === 7) {
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    const inflated = inflateAt(pack, offset);
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch');
    offset = inflated.next;
    const entry: PackEntry = { type, data: inflated.data, baseOid, baseOffset, offset: start };
    entries.push(entry);
    byOffset.set(start, entry);
  }
  const resolved = new Map<string, GitObject>();
  const byOid = new Map<string, PackEntry>();
  const resolvedByOffset = new Map<number, GitObject>();
  // Whole objects first: their ids are computable without resolving anything.
  for (const entry of entries) {
    if (entry.type !== 6 && entry.type !== 7) {
      const type = PACK_TYPES[entry.type];
      if (type === undefined) throw new Error(`unknown pack object type ${entry.type}`);
      const object: GitObject = { type, data: entry.data };
      const oid = hashObject(type, entry.data);
      resolved.set(oid, object);
      byOid.set(oid, entry);
    }
  }
  // Deltas next, in rounds: a delta resolves as soon as its base is known,
  // whether the base came from this pack, from an earlier round, or from the
  // objects the server already holds (a thin pack).
  let pending = entries.filter((entry) => entry.type === 6 || entry.type === 7);
  while (pending.length > 0) {
    const nextPending: PackEntry[] = [];
    let progressed = false;
    for (const entry of pending) {
      let base: GitObject | undefined;
      if (entry.baseOid !== undefined) {
        base = resolved.get(entry.baseOid) ?? have(entry.baseOid);
      } else if (entry.baseOffset !== undefined) {
        const baseEntry = byOffset.get(entry.baseOffset);
        if (baseEntry !== undefined) {
          const baseType = PACK_TYPES[baseEntry.type];
          if (baseType !== undefined) {
            const baseOid = hashObject(baseType, baseEntry.data);
            base = resolved.get(baseOid);
          } else {
            // The base is itself a delta: find it among the resolved deltas by
            // re-resolving is not possible by oid, so look it up by offset in
            // the map of deltas resolved in earlier rounds.
            base = resolvedByOffset.get(entry.baseOffset);
          }
        }
      }
      if (base === undefined) {
        nextPending.push(entry);
        continue;
      }
      const data = applyDelta(base.data, entry.data);
      const object: GitObject = { type: base.type, data };
      const oid = hashObject(object.type, object.data);
      resolved.set(oid, object);
      resolvedByOffset.set(entry.offset, object);
      progressed = true;
    }
    if (!progressed) throw new Error('delta base missing');
    pending = nextPending;
  }
  return resolved;
}

/** Write a packfile of whole objects (no deltas): header, deflated entries, SHA-1 trailer. */
function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  const typeCode: Record<ObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
  for (const object of objects) {
    const size = object.data.length;
    const first = (typeCode[object.type] << 4) | (size & 0x0f);
    const headerBytes: number[] = [];
    let remaining = size >> 4;
    if (remaining === 0) {
      headerBytes.push(first);
    } else {
      headerBytes.push(first | 0x80);
      while (remaining > 0) {
        let byte = remaining & 0x7f;
        remaining >>= 7;
        if (remaining > 0) byte |= 0x80;
        headerBytes.push(byte);
      }
    }
    parts.push(Buffer.from(headerBytes));
    parts.push(deflateSync(object.data, { level: 6 }));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/** Split a pack into sideband band-1 pkt-lines (each at most 65515 data bytes). */
function sidebandPack(pack: Buffer): Buffer {
  const chunks: Buffer[] = [];
  const CHUNK = 65515;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const slice = pack.subarray(offset, Math.min(pack.length, offset + CHUNK));
    chunks.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (chunks.length === 0) chunks.push(pktLine(Buffer.from([1])));
  return Buffer.concat([...chunks, PKT_FLUSH]);
}

// ---------------------------------------------------------------------------
// The store: repositories, issues, pull requests, labels, comments
// ---------------------------------------------------------------------------

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
}

interface Comment {
  id: number;
  body: string;
  createdAt: string;
  updatedAt: string;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  createdAt: string;
  updatedAt: string;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  private: boolean;
  description: string;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Map<string, Label>;
  comments: Map<number, Comment[]>;
  seq: number;
}

const repos = new Map<string, Repo>();
let repoIdSeq = 5000;
let globalIdSeq = 100000;

function repoKey(owner: string, name: string): string {
  return `${owner.toLowerCase()}/${name.toLowerCase()}`;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function globalId(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64url');
}

function repoGlobalId(repo: Repo): string {
  return globalId('repo', `${repo.owner}/${repo.name}`);
}

function issueGlobalId(repo: Repo, issue: Issue): string {
  return globalId('issue', `${repo.owner}/${repo.name}#${issue.number}`);
}

function pullGlobalId(repo: Repo, pull: Pull): string {
  return globalId('pull', `${repo.owner}/${repo.name}#${pull.number}`);
}

function commentGlobalId(repo: Repo, issueNumber: number, comment: Comment): string {
  return globalId('comment', `${repo.owner}/${repo.name}#${issueNumber}:${comment.id}`);
}

/** Decode a global id back to its kind and key, or null. */
function decodeGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64url').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { kind: text.slice(0, colon), key: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

function userJson(): Record<string, unknown> {
  return { login: VIEWER.login, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email, type: 'User', avatar_url: '', html_url: '' };
}

function labelJson(label: Label): Record<string, unknown> {
  return { id: label.id, name: label.name, color: label.color, description: label.description, url: '', default: false };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issueGlobalId(repo, issue),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: userJson(),
    labels: issue.labels.map(labelJson),
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    html_url: '',
    url: '',
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: pullGlobalId(repo, pull),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    user: userJson(),
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}`, repo: { name: repo.name, full_name: `${repo.owner}/${repo.name}` } },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}`, repo: { name: repo.name, full_name: `${repo.owner}/${repo.name}` } },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    html_url: '',
    url: '',
  };
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(),
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_projects: true,
    has_wiki: false,
    has_pages: false,
    has_downloads: true,
    archived: false,
    disabled: false,
    fork: false,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.updatedAt,
    clone_url: '',
    html_url: '',
    url: '',
  };
}

// ---------------------------------------------------------------------------
// Object-graph helpers over one repository
// ---------------------------------------------------------------------------

/** Peel a tag (possibly nested) to the commit it names; commits pass through. */
function peelToCommit(repo: Repo, oid: string): string | null {
  let current = oid;
  for (let depth = 0; depth < 8; depth += 1) {
    const object = repo.objects.get(current);
    if (object === undefined) return null;
    if (object.type === 'commit') return current;
    if (object.type === 'tag') {
      current = parseTag(object.data).object;
      continue;
    }
    return null;
  }
  return null;
}

/** Every object reachable from the given roots (commits, trees, blobs, tags). */
/** Every tree/blob oid under `treeOid`, including the tree itself. */
function treeClosure(repo: Repo, treeOid: string): Set<string> {
  const out = new Set<string>();
  const stack = [treeOid];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    out.add(oid);
    if (object.type === 'tree') for (const entry of parseTree(object.data)) stack.push(entry.oid);
  }
  return out;
}

function reachable(repo: Repo, roots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const view = parseCommit(object.data);
      stack.push(view.tree);
      for (const parent of view.parents) stack.push(parent);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) stack.push(entry.oid);
    } else if (object.type === 'tag') {
      stack.push(parseTag(object.data).object);
    }
  }
  return seen;
}

/** Whether `ancestor` is an ancestor of (or equal to) `commit`. */
function isAncestor(repo: Repo, ancestor: string, commit: string): boolean {
  if (ancestor === commit) return true;
  const seen = new Set<string>();
  const stack = [commit];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) stack.push(parent);
  }
  return false;
}

/** The merge-base of two commits: the nearest common ancestor. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsA = new Map<string, number>();
  const queueA: Array<[string, number]> = [[a, 0]];
  while (queueA.length > 0) {
    const [oid, depth] = queueA.shift() as [string, number];
    if (ancestorsA.has(oid)) continue;
    ancestorsA.set(oid, depth);
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueA.push([parent, depth + 1]);
  }
  const queueB: Array<[string, number]> = [[b, 0]];
  const seenB = new Set<string>();
  let best: string | null = null;
  let bestDepth = Number.POSITIVE_INFINITY;
  while (queueB.length > 0) {
    const [oid, depth] = queueB.shift() as [string, number];
    if (seenB.has(oid)) continue;
    seenB.add(oid);
    const depthA = ancestorsA.get(oid);
    if (depthA !== undefined && depthA + depth < bestDepth) {
      best = oid;
      bestDepth = depthA + depth;
    }
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueB.push([parent, depth + 1]);
  }
  return best;
}

/** The flat path -> blob-oid map of a tree, recursing into subtrees. */
function treeFileMap(repo: Repo, treeOid: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (oid: string, prefix: string): void => {
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, entry.oid);
    }
  };
  walk(treeOid, '');
  return out;
}

/** Build (and store) the tree objects for a flat path -> blob-oid map. */
function buildTreeFromMap(repo: Repo, files: Map<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, oid] of files) {
    const parts = path.split('/');
    let node = root;
    for (let index = 0; index < parts.length - 1; index += 1) {
      const part = parts[index];
      if (!node.dirs.has(part)) node.dirs.set(part, make());
      node = node.dirs.get(part) as Node;
    }
    node.files.set(parts[parts.length - 1], oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

/** Store an object if new; return its oid. */
function putObject(repo: Repo, type: ObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

/**
 * Create a commit on top of `parentOids` (empty for a root commit) applying
 * `changes` (path -> new blob bytes, or null to delete) to the first
 * parent's tree, or to an empty tree when there is no parent.
 */
function makeCommit(repo: Repo, parentOids: readonly string[], changes: Map<string, Buffer | null>, message: string): string {
  const baseFiles = parentOids.length > 0 ? treeFileMap(repo, parseCommit((repo.objects.get(parentOids[0]) as GitObject).data).tree) : new Map<string, string>();
  for (const [path, content] of changes) {
    if (content === null) baseFiles.delete(path);
    else baseFiles.set(path, putObject(repo, 'blob', content));
  }
  const treeOid = buildTreeFromMap(repo, baseFiles);
  const when = Math.floor(Date.now() / 1000);
  const data = buildCommit({ tree: treeOid, parents: parentOids, author: identityLine(when), committer: identityLine(when), message });
  return putObject(repo, 'commit', data);
}

/** Resolve a ref-ish (branch name, full ref, or oid) to a commit oid, or null. */
function resolveRef(repo: Repo, ref: string): string | null {
  if (/^[0-9a-f]{40}$/.test(ref)) return repo.objects.has(ref) ? ref : null;
  if (ref.startsWith('refs/')) {
    const oid = repo.refs.get(ref);
    return oid === undefined ? null : oid;
  }
  const oid = repo.refs.get(`refs/heads/${ref}`);
  return oid === undefined ? null : oid;
}

/** List commits reachable from `tip`, newest first (by author time, then insertion). */
function listCommits(repo: Repo, tip: string): Array<{ sha: string; view: CommitView; stamp: number }> {
  const seen = new Set<string>();
  const stack = [tip];
  const out: Array<{ sha: string; view: CommitView; stamp: number }> = [];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    const view = parseCommit(object.data);
    const stampMatch = / (\d+) \+0000$/.exec(view.author);
    out.push({ sha: oid, view, stamp: stampMatch === null ? 0 : Number(stampMatch[1]) });
    for (const parent of view.parents) stack.push(parent);
  }
  out.sort((a, b) => b.stamp - a.stamp);
  return out;
}

function commitJson(sha: string, view: CommitView): Record<string, unknown> {
  const parseIdentity = (line: string): { name: string; email: string; date: string } => {
    const match = /^(.*) <(.*)> (\d+) ([+-]\d{4})$/.exec(line);
    if (match === null) return { name: line, email: '', date: nowIso() };
    return { name: match[1], email: match[2], date: new Date(Number(match[3]) * 1000).toISOString() };
  };
  const author = parseIdentity(view.author);
  const committer = parseIdentity(view.committer);
  return {
    sha,
    commit: {
      // The stored object keeps its trailing newline; the API view does not.
      message: view.message.replace(/\n+$/, ''),
      author: { ...author, login: VIEWER.login },
      committer: { ...committer, login: VIEWER.login },
      tree: { sha: view.tree },
    },
    author: userJson(),
    committer: userJson(),
    parents: view.parents.map((parent) => ({ sha: parent })),
  };
}

/** Diff two file maps: path -> {status, additions, deletions}. */
function diffFileMaps(repo: Repo, before: Map<string, string>, after: Map<string, string>): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  const paths = new Set([...before.keys(), ...after.keys()]);
  const lineMultiset = (oid: string | undefined): Map<string, number> => {
    const counts = new Map<string, number>();
    if (oid === undefined) return counts;
    const object = repo.objects.get(oid);
    if (object === undefined) return counts;
    for (const line of object.data.toString('utf8').split('\n')) counts.set(line, (counts.get(line) ?? 0) + 1);
    return counts;
  };
  const countNewLines = (from: Map<string, number>, to: Map<string, number>): number => {
    let total = 0;
    for (const [line, count] of to) total += Math.max(0, count - (from.get(line) ?? 0));
    return total;
  };
  for (const path of [...paths].sort()) {
    const oldOid = before.get(path);
    const newOid = after.get(path);
    if (oldOid === newOid) continue;
    if (oldOid === undefined) {
      const additions = lineMultiset(newOid).size === 0 ? 0 : [...lineMultiset(newOid).values()].reduce((sum, n) => sum + n, 0);
      out.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (newOid === undefined) {
      const deletions = [...lineMultiset(oldOid).values()].reduce((sum, n) => sum + n, 0);
      out.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    } else {
      const additions = countNewLines(lineMultiset(oldOid), lineMultiset(newOid));
      const deletions = countNewLines(lineMultiset(newOid), lineMultiset(oldOid));
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

/** The changed files of a pull request (base tip tree vs head tip tree). */
function pullFiles(repo: Repo, pull: Pull): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const baseCommit = repo.objects.get(pull.baseSha);
  const headCommit = repo.objects.get(pull.headSha);
  if (baseCommit === undefined || headCommit === undefined) return [];
  const baseFiles = treeFileMap(repo, parseCommit(baseCommit.data).tree);
  const headFiles = treeFileMap(repo, parseCommit(headCommit.data).tree);
  return diffFileMaps(repo, baseFiles, headFiles);
}

/** Whether merging `pull` would conflict (same path changed both sides, differently). */
function pullConflicts(repo: Repo, pull: Pull): boolean {
  // The base side is the branch's tip *now*, not the tip recorded when the
  // pull request was opened: a first merge can move the base under a second
  // pull request, and that is exactly when a conflict appears.
  const baseTip = branchTip(repo, pull.baseRef) ?? pull.baseSha;
  const base = mergeBase(repo, baseTip, pull.headSha);
  if (base === null) return true;
  const baseCommit = repo.objects.get(base);
  const headCommit = repo.objects.get(pull.headSha);
  const baseTipCommit = repo.objects.get(baseTip);
  if (baseCommit === undefined || headCommit === undefined || baseTipCommit === undefined) return true;
  const ancestorFiles = treeFileMap(repo, parseCommit(baseCommit.data).tree);
  const headFiles = treeFileMap(repo, parseCommit(headCommit.data).tree);
  const baseFiles = treeFileMap(repo, parseCommit(baseTipCommit.data).tree);
  const paths = new Set([...ancestorFiles.keys(), ...headFiles.keys(), ...baseFiles.keys()]);
  for (const path of paths) {
    const a = ancestorFiles.get(path);
    const h = headFiles.get(path);
    const b = baseFiles.get(path);
    const headChanged = h !== a;
    const baseChanged = b !== a;
    if (headChanged && baseChanged && h !== b) return true;
  }
  return false;
}

function pullMergeable(repo: Repo, pull: Pull): 'MERGEABLE' | 'CONFLICTING' {
  if (pull.state !== 'open') return 'CONFLICTING';
  return pullConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
}

/** Squash-merge a pull request onto its base branch; returns the merge commit oid or null on conflict. */
function squashMerge(repo: Repo, pull: Pull, message: string): string | null {
  if (pull.state !== 'open') return null;
  if (pullConflicts(repo, pull)) return null;
  const baseTip = branchTip(repo, pull.baseRef) ?? pull.baseSha;
  const base = mergeBase(repo, baseTip, pull.headSha);
  const headCommit = repo.objects.get(pull.headSha);
  const baseTipCommit = repo.objects.get(baseTip);
  if (headCommit === undefined || baseTipCommit === undefined) return null;
  const headFiles = treeFileMap(repo, parseCommit(headCommit.data).tree);
  const baseFiles = treeFileMap(repo, parseCommit(baseTipCommit.data).tree);
  const ancestorFiles = base === null ? new Map<string, string>() : treeFileMap(repo, parseCommit((repo.objects.get(base) as GitObject).data).tree);
  const merged = new Map(baseFiles);
  for (const [path, oid] of headFiles) {
    if (ancestorFiles.get(path) !== oid) merged.set(path, oid);
  }
  for (const path of ancestorFiles.keys()) {
    if (!headFiles.has(path) && baseFiles.get(path) === ancestorFiles.get(path)) merged.delete(path);
  }
  const treeOid = buildTreeFromMap(repo, merged);
  const when = Math.floor(Date.now() / 1000);
  const data = buildCommit({
    tree: treeOid,
    parents: [baseTip],
    author: identityLine(when),
    committer: identityLine(when),
    message: message !== '' ? message : `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}`,
  });
  const mergeOid = putObject(repo, 'commit', data);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeOid);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = nowIso();
  pull.mergeCommitSha = mergeOid;
  pull.updatedAt = nowIso();
  repo.updatedAt = nowIso();
  return mergeOid;
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

interface AdvertisedRef {
  oid: string;
  name: string;
  peeled?: string;
  symrefTarget?: string;
}

function advertisedRefs(repo: Repo): AdvertisedRef[] {
  const refs: AdvertisedRef[] = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  if (headOid !== undefined) refs.push({ oid: headOid, name: 'HEAD', symrefTarget: headTarget });
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    const object = repo.objects.get(oid);
    const entry: AdvertisedRef = { oid, name };
    if (object !== undefined && object.type === 'tag') {
      const target = parseTag(object.data).object;
      const peeled = peelToCommit(repo, oid);
      if (peeled !== null && peeled !== target) entry.peeled = peeled;
      else if (peeled !== null) entry.peeled = peeled;
    }
    refs.push(entry);
  }
  return refs;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const refs = advertisedRefs(repo);
  const capabilities =
    service === 'git-upload-pack'
      ? 'side-band-64k thin-pack ofs-delta shallow multi_ack_detailed symref=HEAD:refs/heads/main agent=github-core-clone/1.0'
      : 'report-status side-band-64k delete-refs ofs-delta symref=HEAD:refs/heads/main agent=github-core-clone/1.0';
  const lines: Array<string | 'flush'> = [`# service=${service}\n`, 'flush'];
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${capabilities}\n`);
  } else {
    refs.forEach((ref, index) => {
      const caps = index === 0 ? `\0${capabilities}` : '';
      lines.push(`${ref.oid} ${ref.name}${caps}\n`);
      if (ref.peeled !== undefined) lines.push(`${ref.peeled} ${ref.name}^{}\n`);
    });
  }
  // The ref list ends with a flush: real git waits for it and reports
  // "the remote end hung up" when the body just ends instead.
  lines.push('flush');
  return pktLines(lines);
}

function v2Advertisement(): Buffer {
  return pktLines(['version 2\n', 'ls-refs=unborn\n', 'fetch=shallow filter\n', 'object-format=sha1\n', `agent=${AGENT}\n`, 'flush']);
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, repo: Repo | undefined, service: 'git-upload-pack' | 'git-receive-pack'): void {
  if (repo === undefined) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const wantsV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
  const body = wantsV2 ? v2Advertisement() : v0Advertisement(repo, service);
  sendRaw(res, 200, body, `application/x-${service}-advertisement`);
}

/** The objects a fetch must send for `wants`, minus what `haves` already hold, honoring `depth`. */
function planFetch(repo: Repo, wants: readonly string[], haves: readonly string[], depth: number | null, priorShallow: readonly string[]): { objects: GitObject[]; shallow: string[]; unshallow: string[] } {
  // What the client already holds. A shallow client's history stops at its
  // boundary commits: a `have` at the boundary does NOT imply the client
  // holds that commit's parents (that is what makes the clone shallow), so
  // the walk stops there — the boundary itself is included. With no
  // boundary this is the usual full reachable set. Getting this wrong
  // silently drops the very commits a deepen asks for.
  const boundary = new Set(priorShallow);
  const haveCommits = new Set<string>();
  const haveQueue = [...haves];
  while (haveQueue.length > 0) {
    const oid = haveQueue.shift() as string;
    if (haveCommits.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    const commitOid = object.type === 'tag' ? peelToCommit(repo, oid) : oid;
    if (commitOid === null || haveCommits.has(commitOid)) continue;
    haveCommits.add(commitOid);
    if (boundary.has(commitOid)) continue;
    const commitObject = repo.objects.get(commitOid);
    if (commitObject !== undefined && commitObject.type === 'commit') {
      for (const parent of parseCommit(commitObject.data).parents) haveQueue.push(parent);
    }
  }
  const haveReachable = new Set<string>();
  for (const oid of haveCommits) {
    haveReachable.add(oid);
    const commitObject = repo.objects.get(oid);
    if (commitObject !== undefined && commitObject.type === 'commit') {
      for (const treeOid of treeClosure(repo, parseCommit(commitObject.data).tree)) haveReachable.add(treeOid);
    }
  }
  for (const have of haves) {
    const object = repo.objects.get(have);
    if (object !== undefined && object.type === 'tag') haveReachable.add(have);
  }
  const wanted = new Set<string>();
  const shallow = new Set<string>();
  const unshallow = new Set<string>();
  const queue: Array<{ oid: string; depth: number }> = wants.map((oid) => ({ oid, depth: 0 }));
  const seenCommits = new Set<string>();
  while (queue.length > 0) {
    const { oid, depth: at } = queue.shift() as { oid: string; depth: number };
    if (seenCommits.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    const commitOid = object.type === 'tag' ? peelToCommit(repo, oid) : oid;
    if (commitOid === null) continue;
    if (object.type === 'tag') {
      if (!haveReachable.has(oid)) wanted.add(oid);
    }
    if (seenCommits.has(commitOid)) continue;
    seenCommits.add(commitOid);
    const commitObject = repo.objects.get(commitOid);
    if (commitObject === undefined || commitObject.type !== 'commit') continue;
    if (!haveReachable.has(commitOid)) wanted.add(commitOid);
    const view = parseCommit(commitObject.data);
    const atLimit = depth !== null && at + 1 >= depth;
    if (atLimit) {
      if (view.parents.length > 0) shallow.add(commitOid);
      continue;
    }
    for (const parent of view.parents) queue.push({ oid: parent, depth: at + 1 });
  }
  for (const oid of priorShallow) {
    if (seenCommits.has(oid) && !shallow.has(oid)) unshallow.add(oid);
  }
  // The pack carries exactly the depth-bounded commit set plus each such
  // commit's tree closure (trees, blobs, and any tag objects the wants name).
  // Commit parents are never followed here: that is what makes a shallow
  // fetch shallow — the old code re-expanded `wanted` through reachable(),
  // which walks parents and shipped the whole history.
  const all = new Set<string>();
  const stack: string[] = [];
  for (const oid of wanted) stack.push(oid);
  for (const oid of seenCommits) if (!haveReachable.has(oid)) stack.push(oid);
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (all.has(oid) || haveReachable.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    all.add(oid);
    if (object.type === 'commit') stack.push(parseCommit(object.data).tree);
    else if (object.type === 'tree') for (const entry of parseTree(object.data)) stack.push(entry.oid);
    else if (object.type === 'tag') stack.push(parseTag(object.data).object);
  }
  const objects: GitObject[] = [];
  for (const oid of all) {
    const object = repo.objects.get(oid);
    if (object !== undefined) objects.push(object);
  }
  return { objects, shallow: [...shallow], unshallow: [...unshallow] };
}

async function handleUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const raw = await readBody(req);
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  const { packets } = decodePackets(raw);
  if (packets.length === 0 || packets[0].kind !== 'data') {
    badRequest(res, 'malformed pkt-line stream');
    return;
  }
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  if (!isV2) {
    // v0 fetch: want lines, flush, have lines, done, flush.
    const wants: string[] = [];
    const haves: string[] = [];
    const shallows: string[] = [];
    let depth: number | null = null;
    for (const line of lines) {
      const text = line.replace(/\n$/, '');
      if (text.startsWith('want ')) wants.push(text.slice(5).split(' ')[0]);
      else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
      else if (text.startsWith('shallow ')) shallows.push(text.slice(8).trim());
      else if (text.startsWith('deepen ')) depth = Number(text.slice(7).trim());
    }
    const plan = planFetch(repo, wants, haves, depth, shallows);
    const pack = writePack(plan.objects);
    const out: Buffer[] = [];
    if (haves.length === 0) out.push(pktLine('NAK\n'));
    else {
      for (const have of haves) if (repo.objects.has(have)) out.push(pktLine(`ACK ${have}\n`));
      out.push(pktLine('ready\n'));
    }
    for (const oid of plan.shallow) out.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) out.push(pktLine(`unshallow ${oid}\n`));
    out.push(sidebandPack(pack));
    sendRaw(res, 200, Buffer.concat(out), 'application/x-git-upload-pack-result');
    return;
  }
  // v2: command line, args, delim, then command arguments until flush.
  const commandLine = (lines[0] ?? '').replace(/\n$/, '');
  const command = commandLine.startsWith('command=') ? commandLine.slice('command='.length) : '';
  const args = lines.slice(1);
  if (command === 'ls-refs') {
    const prefixes: string[] = [];
    let peel = false;
    let symrefs = false;
    for (const arg of args) {
      const text = arg.replace(/\n$/, '');
      if (text === 'peel') peel = true;
      else if (text === 'symrefs') symrefs = true;
      else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
    }
    const refs = advertisedRefs(repo);
    const out: string[] = [];
    const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
    if (refs.length === 0) {
      if (keep('HEAD')) out.push(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
    } else {
      for (const ref of refs) {
        if (!keep(ref.name)) continue;
        let line = `${ref.oid} ${ref.name}`;
        if (ref.name === 'HEAD' && symrefs && ref.symrefTarget !== undefined) line += ` symref-target:${ref.symrefTarget}`;
        if (peel && ref.peeled !== undefined) line += ` peeled:${ref.peeled}`;
        out.push(`${line}\n`);
      }
    }
    sendRaw(res, 200, pktLines([...out, 'flush']), 'application/x-git-upload-pack-result');
    return;
  }
  if (command === 'fetch') {
    const wants: string[] = [];
    const haves: string[] = [];
    const shallows: string[] = [];
    let depth: number | null = null;
    for (const arg of args) {
      const text = arg.replace(/\n$/, '');
      if (text.startsWith('want ')) wants.push(text.slice(5).trim());
      else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
      else if (text.startsWith('shallow ')) shallows.push(text.slice(8).trim());
      else if (text.startsWith('deepen ')) depth = Number(text.slice(7).trim());
    }
    const plan = planFetch(repo, wants, haves, depth, shallows);
    const pack = writePack(plan.objects);
    const out: Buffer[] = [];
    if (haves.length > 0) {
      out.push(pktLine('acknowledgments\n'));
      let acknowledged = false;
      for (const have of haves) {
        if (repo.objects.has(have)) {
          out.push(pktLine(`ACK ${have}\n`));
          acknowledged = true;
        }
      }
      if (!acknowledged) out.push(pktLine('NAK\n'));
      else out.push(pktLine('ready\n'));
      out.push(PKT_DELIM);
    }
    if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
      out.push(pktLine('shallow-info\n'));
      for (const oid of plan.shallow) out.push(pktLine(`shallow ${oid}\n`));
      for (const oid of plan.unshallow) out.push(pktLine(`unshallow ${oid}\n`));
      out.push(PKT_DELIM);
    }
    out.push(pktLine('packfile\n'));
    out.push(sidebandPack(pack));
    sendRaw(res, 200, Buffer.concat(out), 'application/x-git-upload-pack-result');
    return;
  }
  badRequest(res, `unknown v2 command ${command}`);
}

async function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const raw = await readBody(req);
  const { packets, rest } = decodePackets(raw);
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let sawFlush = false;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      sawFlush = true;
      break;
    }
    if (packet.kind !== 'data') continue;
    let line = packet.payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul);
    const parts = line.split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
    }
  }
  if (!sawFlush || commands.length === 0) {
    badRequest(res, 'malformed receive-pack stream');
    return;
  }
  let unpackOk = true;
  let unpackDetail = 'ok';
  let incoming = new Map<string, GitObject>();
  if (rest < raw.length) {
    try {
      incoming = readPack(raw.subarray(rest), (oid) => repo.objects.get(oid));
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }
  const reportLines: string[] = [];
  if (unpackOk) {
    for (const [oid, object] of incoming) repo.objects.set(oid, object);
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      let problem: string | null = null;
      if (command.newOid === ZERO_OID) {
        if (current === undefined) problem = 'no such ref';
        else if (command.oldOid !== ZERO_OID && command.oldOid !== current) problem = 'old ref does not match';
      } else {
        const target = repo.objects.get(command.newOid);
        if (target === undefined) problem = 'object not found';
        else if (target.type !== 'commit' && target.type !== 'tag') problem = 'not a commit';
        else if (command.oldOid === ZERO_OID) {
          if (current !== undefined) problem = 'already exists';
        } else {
          if (current === undefined) problem = 'non-fast-forward';
          else if (command.oldOid !== current) problem = 'non-fast-forward';
          else {
            const newCommit = peelToCommit(repo, command.newOid);
            const oldCommit = peelToCommit(repo, current);
            if (newCommit === null || oldCommit === null) problem = 'non-fast-forward';
            else if (!isAncestor(repo, oldCommit, newCommit)) problem = 'non-fast-forward';
          }
        }
      }
      if (problem === null) {
        if (command.newOid === ZERO_OID) repo.refs.delete(command.ref);
        else repo.refs.set(command.ref, command.newOid);
        reportLines.push(`ok ${command.ref}\n`);
      } else {
        reportLines.push(`ng ${command.ref} ${problem}\n`);
      }
    }
    repo.updatedAt = nowIso();
  }
  // The report-status stream inside band 1 is itself pkt-framed and ends
  // with its own flush: real git's status reader loops on pkt-lines until
  // that flush and dies ("the remote end hung up unexpectedly") on EOF
  // without it. The outer flush then ends the sideband stream.
  const inner = pktLines([`unpack ${unpackOk ? 'ok' : unpackDetail}\n`, ...reportLines, 'flush']);
  const outer = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), inner])), PKT_FLUSH]);
  sendRaw(res, 200, outer, 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function baseUrlOf(req: IncomingMessage): string {
  const host = req.headers.host ?? '127.0.0.1';
  return `http://${host}`;
}

function paginate<T>(items: readonly T[], query: URLSearchParams): { page: T[]; total: number; perPage: number; pageNum: number } {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) ? Math.min(100, Math.max(1, Math.trunc(perPageRaw))) : 30;
  const pageRaw = Number(query.get('page') ?? '1');
  const pageNum = Number.isFinite(pageRaw) ? Math.max(1, Math.trunc(pageRaw)) : 1;
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), total: items.length, perPage, pageNum };
}

function linkHeader(req: IncomingMessage, path: string, query: URLSearchParams, total: number, perPage: number, pageNum: number): string {
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const urlFor = (page: number): string => {
    const params = new URLSearchParams(query);
    params.set('per_page', String(perPage));
    params.set('page', String(page));
    return `${baseUrlOf(req)}${path}?${params.toString()}`;
  };
  const links: string[] = [];
  if (pageNum < totalPages) links.push(`<${urlFor(pageNum + 1)}>; rel="next"`);
  if (pageNum > 1) links.push(`<${urlFor(pageNum - 1)}>; rel="prev"`);
  links.push(`<${urlFor(1)}>; rel="first"`);
  links.push(`<${urlFor(totalPages)}>; rel="last"`);
  return links.join(', ');
}

function listWithPagination<T>(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams, items: readonly T[]): void {
  const { page, total, perPage, pageNum } = paginate(items, query);
  const link = linkHeader(req, path, query, total, perPage, pageNum);
  sendJson(res, 200, page, { link });
}

/** A repo-scoped route: the owner must be the viewer, and the repo must exist. */
function repoRoute(segments: string[]): { owner: string; name: string } | null {
  if (segments.length < 2) return null;
  return { owner: segments[0], name: segments[1] };
}

function lookupRepoOr404(res: ServerResponse, owner: string, name: string): Repo | null {
  if (owner.toLowerCase() !== VIEWER.login.toLowerCase()) {
    sendJson(res, 404, { message: 'Not Found' });
    return null;
  }
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendJson(res, 404, { message: 'Not Found' });
    return null;
  }
  return repo;
}

function createRepo(name: string, isPrivate: boolean, description: string, defaultBranch: string): Repo {
  const now = nowIso();
  const repo: Repo = {
    id: repoIdSeq,
    name,
    owner: VIEWER.login,
    private: isPrivate,
    description,
    defaultBranch,
    createdAt: now,
    updatedAt: now,
    objects: new Map(),
    refs: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Map(),
    comments: new Map(),
    seq: 0,
  };
  repoIdSeq += 1;
  repos.set(repoKey(VIEWER.login, name), repo);
  return repo;
}

function branchTip(repo: Repo, branch: string): string | null {
  const oid = repo.refs.get(`refs/heads/${branch}`);
  return oid === undefined ? null : oid;
}

function treeAtTip(repo: Repo, tip: string | null): Map<string, string> {
  if (tip === null) return new Map();
  const commit = repo.objects.get(tip);
  if (commit === undefined || commit.type !== 'commit') return new Map();
  return treeFileMap(repo, parseCommit(commit.data).tree);
}

async function handleContentsPut(req: IncomingMessage, res: ServerResponse, repo: Repo, pathParts: string[], body: Record<string, unknown>): Promise<void> {
  const filePath = pathParts.join('/');
  if (filePath === '') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const message = typeof body.message === 'string' && body.message !== '' ? body.message : `Update ${filePath}`;
  const contentB64 = typeof body.content === 'string' ? body.content : '';
  const content = Buffer.from(contentB64.replace(/\s+/g, ''), 'base64');
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  let tip = branchTip(repo, branch);
  if (tip === null) {
    const defaultTip = branchTip(repo, repo.defaultBranch);
    if (defaultTip !== null) {
      repo.refs.set(`refs/heads/${branch}`, defaultTip);
      tip = defaultTip;
    }
  }
  const files = treeAtTip(repo, tip);
  const existing = files.get(filePath);
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  if (existing !== undefined) {
    if (sha === undefined) {
      sendJson(res, 422, { message: 'sha is required to update an existing file' });
      return;
    }
    if (sha.toLowerCase() !== existing.toLowerCase()) {
      sendJson(res, 409, { message: 'sha does not match the current file' });
      return;
    }
  } else if (sha !== undefined) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const parents = tip === null ? [] : [tip];
  const changes = new Map<string, Buffer | null>([[filePath, content]]);
  const commitOid = makeCommit(repo, parents, changes, message);
  repo.refs.set(`refs/heads/${branch}`, commitOid);
  repo.updatedAt = nowIso();
  const blobOid = putObject(repo, 'blob', content);
  const status = existing === undefined ? 201 : 200;
  sendJson(res, status, {
    content: { name: filePath.split('/').pop() ?? filePath, path: filePath, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', url: '' },
    commit: { sha: commitOid, message, author: { name: VIEWER.name, email: VIEWER.email, date: nowIso() }, committer: { name: VIEWER.name, email: VIEWER.email, date: nowIso() } },
  });
}

async function handleContentsDelete(req: IncomingMessage, res: ServerResponse, repo: Repo, pathParts: string[], body: Record<string, unknown> | undefined): Promise<void> {
  const filePath = pathParts.join('/');
  const branch = body !== undefined && typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const tip = branchTip(repo, branch);
  const files = treeAtTip(repo, tip);
  const existing = files.get(filePath);
  if (existing === undefined) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const sha = body !== undefined && typeof body.sha === 'string' ? body.sha : undefined;
  if (sha !== undefined && sha.toLowerCase() !== existing.toLowerCase()) {
    sendJson(res, 409, { message: 'sha does not match the current file' });
    return;
  }
  const message = body !== undefined && typeof body.message === 'string' && body.message !== '' ? body.message : `Delete ${filePath}`;
  const parents = tip === null ? [] : [tip];
  const commitOid = makeCommit(repo, parents, new Map([[filePath, null]]), message);
  repo.refs.set(`refs/heads/${branch}`, commitOid);
  repo.updatedAt = nowIso();
  sendJson(res, 200, { commit: { sha: commitOid, message } });
}

function handleContentsGet(req: IncomingMessage, res: ServerResponse, repo: Repo, pathParts: string[], query: URLSearchParams): void {
  const filePath = pathParts.join('/');
  const ref = query.get('ref') ?? undefined;
  let tip: string | null;
  if (ref === undefined) tip = branchTip(repo, repo.defaultBranch);
  else {
    const resolved = resolveRef(repo, ref);
    tip = resolved;
  }
  if (tip === null) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const commit = repo.objects.get(tip);
  if (commit === undefined || commit.type !== 'commit') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const rootTree = parseCommit(commit.data).tree;
  if (filePath === '') {
    const entries = entriesOfDir(repo, rootTree, '');
    sendJson(res, 200, entries);
    return;
  }
  const files = treeFileMap(repo, rootTree);
  const blobOid = files.get(filePath);
  if (blobOid !== undefined) {
    const blob = repo.objects.get(blobOid) as GitObject;
    sendJson(res, 200, {
      type: 'file',
      encoding: 'base64',
      size: blob.data.length,
      name: filePath.split('/').pop() ?? filePath,
      path: filePath,
      sha: blobOid,
      content: blob.data.toString('base64'),
      url: '',
    });
    return;
  }
  // A directory: list the entries directly under it.
  const prefix = `${filePath}/`;
  const direct = new Map<string, { type: string; oid: string }>();
  for (const [path, oid] of files) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) direct.set(rest, { type: 'file', oid });
    else direct.set(rest.slice(0, slash), { type: 'dir', oid: '' });
  }
  if (direct.size === 0) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const dirTreeOid = treeOidAtPath(repo, rootTree, filePath);
  const entries: Array<Record<string, unknown>> = [];
  for (const name of [...direct.keys()].sort()) {
    const entry = direct.get(name) as { type: string; oid: string };
    if (entry.type === 'file') {
      const blob = repo.objects.get(entry.oid) as GitObject;
      entries.push({ type: 'file', name, path: `${filePath}/${name}`, sha: entry.oid, size: blob.data.length, url: '' });
    } else {
      const subTree = dirTreeOid === null ? '' : treeOidAtPath(repo, rootTree, `${filePath}/${name}`) ?? '';
      entries.push({ type: 'dir', name, path: `${filePath}/${name}`, sha: subTree, size: 0, url: '' });
    }
  }
  void dirTreeOid;
  sendJson(res, 200, entries);
}

function entriesOfDir(repo: Repo, treeOid: string, prefix: string): Array<Record<string, unknown>> {
  const object = repo.objects.get(treeOid);
  if (object === undefined || object.type !== 'tree') return [];
  const entries: Array<Record<string, unknown>> = [];
  for (const entry of parseTree(object.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') entries.push({ type: 'dir', name: entry.name, path, sha: entry.oid, size: 0, url: '' });
    else {
      const blob = repo.objects.get(entry.oid);
      entries.push({ type: 'file', name: entry.name, path, sha: entry.oid, size: blob === undefined ? 0 : blob.data.length, url: '' });
    }
  }
  return entries;
}

function treeOidAtPath(repo: Repo, treeOid: string, path: string): string | null {
  let current = treeOid;
  for (const part of path.split('/')) {
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((candidate) => candidate.name === part);
    if (entry === undefined) return null;
    current = entry.oid;
  }
  return current;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, method: string, query: URLSearchParams): Promise<void> {
  const segments = segmentsOf(path.replace(/^\/api\/v3\/?/, ''));
  const raw = method === 'GET' ? null : await readBody(req);
  let body: unknown;
  if (raw !== null) {
    const parsed = parseJsonBody(raw);
    if (!parsed.ok) {
      badRequest(res, 'Invalid JSON body');
      return;
    }
    body = parsed.value;
  }
  const record = (value: unknown): Record<string, unknown> | null =>
    value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;

  // The API root and meta are public; everything else needs the token.
  if (method === 'GET' && segments.length === 0) {
    sendJson(
      res,
      200,
      {
        current_user_url: '/api/v3/user',
        current_user_authorizations_html_url: '',
        authorizations_url: '',
        code_search_url: '',
        commit_search_url: '',
        emails_url: '/api/v3/user/emails',
        emojis_url: '',
        events_url: '',
        feeds_url: '',
        followers_url: '',
        following_url: '',
        gists_url: '',
        hub_url: '',
        issue_search_url: '',
        issues_url: '',
        keys_url: '',
        label_search_url: '',
        notifications_url: '',
        organization_repositories_url: '',
        organization_teams_url: '',
        public_gists_url: '',
        rate_limit_url: '/api/v3/rate_limit',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        repository_search_url: '',
        current_user_repositories_url: '/api/v3/user/repos',
        starred_url: '',
        starred_gists_url: '',
        topic_search_url: '',
        user_url: '/api/v3/users/{user}',
        user_organizations_url: '',
        search_url: '',
        user_search_url: '',
      },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
    return;
  }
  if (method === 'GET' && segments.length === 1 && segments[0] === 'meta') {
    sendJson(res, 200, { installed_version: FORGE_VERSION, verifiable_password_authentication: true, git: ['github.com'], hooks: [] });
    return;
  }
  if (method === 'GET' && segments.length === 1 && segments[0] === 'rate_limit') {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 4999, reset: Math.floor(Date.now() / 1000) + 3600, used: 1 } }, rate: { limit: 5000, remaining: 4999, reset: Math.floor(Date.now() / 1000) + 3600, used: 1 } });
    return;
  }
  if (!authed(req)) {
    unauthorized(res);
    return;
  }

  // GET /user
  if (method === 'GET' && segments.length === 1 && segments[0] === 'user') {
    sendJson(res, 200, { ...userJson(), public_repos: repos.size, followers: 0, following: 0, created_at: '2025-01-01T00:00:00Z', updated_at: nowIso() });
    return;
  }

  // /user/repos
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'GET') {
      const mine = [...repos.values()].filter((repo) => repo.owner.toLowerCase() === VIEWER.login.toLowerCase());
      listWithPagination(req, res, path, query, mine.map(repoJson));
      return;
    }
    if (method === 'POST') {
      const input = record(body) ?? {};
      const name = typeof input.name === 'string' ? input.name.trim() : '';
      if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
        sendJson(res, 422, { message: 'Invalid repository name' });
        return;
      }
      if (findRepo(VIEWER.login, name) !== undefined) {
        sendJson(res, 422, { message: 'Repository already exists' });
        return;
      }
      const repo = createRepo(
        name,
        input.private === true,
        typeof input.description === 'string' ? input.description : '',
        typeof input.default_branch === 'string' && input.default_branch !== '' ? input.default_branch : 'main',
      );
      sendJson(res, 201, repoJson(repo));
      return;
    }
  }

  // /repos/{owner}/{repo}...
  if (segments.length >= 2 && segments[0] === 'repos') {
    const route = repoRoute(segments.slice(1));
    if (route === null) {
      notFound(res);
      return;
    }
    const { owner, name } = route;
    const repo = lookupRepoOr404(res, owner, name);
    if (repo === null) return;
    const rest = segments.slice(3);

    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'PATCH') {
        const input = record(body) ?? {};
        if (typeof input.description === 'string') repo.description = input.description;
        if (typeof input.private === 'boolean') repo.private = input.private;
        if (typeof input.default_branch === 'string' && input.default_branch !== '') repo.defaultBranch = input.default_branch;
        repo.updatedAt = nowIso();
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        sendJson(res, 204, null);
        return;
      }
      notFound(res);
      return;
    }

    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const branches = [...repo.refs.keys()]
          .filter((ref) => ref.startsWith('refs/heads/'))
          .map((ref) => ref.slice('refs/heads/'.length))
          .sort()
          .map((branch) => ({ name: branch, commit: { sha: repo.refs.get(`refs/heads/${branch}`) }, protected: false }));
        sendJson(res, 200, branches);
        return;
      }
      if (method === 'GET' && rest.length === 2) {
        const branch = rest[1];
        const tip = branchTip(repo, branch);
        if (tip === null) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        sendJson(res, 200, { name: branch, commit: { sha: tip }, protected: false });
        return;
      }
      notFound(res);
      return;
    }

    if (rest[0] === 'commits') {
      if (method === 'GET' && rest.length === 1) {
        const sha = query.get('sha') ?? repo.defaultBranch;
        const tip = resolveRef(repo, sha);
        if (tip === null) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        const commits = listCommits(repo, tip).map((entry) => commitJson(entry.sha, entry.view));
        listWithPagination(req, res, path, query, commits);
        return;
      }
      if (method === 'GET' && rest.length === 2) {
        const tip = resolveRef(repo, rest[1]);
        if (tip === null) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        const object = repo.objects.get(tip);
        if (object === undefined || object.type !== 'commit') {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        sendJson(res, 200, commitJson(tip, parseCommit(object.data)));
        return;
      }
      notFound(res);
      return;
    }

    if (rest[0] === 'contents') {
      const pathParts = rest.slice(1);
      if (method === 'GET') {
        handleContentsGet(req, res, repo, pathParts, query);
        return;
      }
      if (method === 'PUT') {
        await handleContentsPut(req, res, repo, pathParts, record(body) ?? {});
        return;
      }
      if (method === 'DELETE') {
        await handleContentsDelete(req, res, repo, pathParts, record(body) ?? undefined);
        return;
      }
      notFound(res);
      return;
    }

    if (rest[0] === 'labels') {
      if (method === 'GET' && rest.length === 1) {
        sendJson(res, 200, [...repo.labels.values()].map(labelJson));
        return;
      }
      if (method === 'POST' && rest.length === 1) {
        const input = record(body) ?? {};
        const labelName = typeof input.name === 'string' ? input.name.trim() : '';
        if (labelName === '') {
          sendJson(res, 422, { message: 'Label name is required' });
          return;
        }
        const existing = [...repo.labels.values()].find((label) => label.name.toLowerCase() === labelName.toLowerCase());
        if (existing !== undefined) {
          sendJson(res, 422, { message: 'Label already exists' });
          return;
        }
        const label: Label = {
          id: globalIdSeq,
          name: labelName,
          color: typeof input.color === 'string' ? input.color : 'ededed',
          description: typeof input.description === 'string' ? input.description : '',
        };
        globalIdSeq += 1;
        repo.labels.set(label.name, label);
        sendJson(res, 201, labelJson(label));
        return;
      }
      notFound(res);
      return;
    }

    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'GET' && rest.length === 2) {
        const all = [...repo.refs.entries()].map(([ref, sha]) => ({ ref, object: { sha, type: 'commit' }, url: '' }));
        sendJson(res, 200, all);
        return;
      }
      if (method === 'GET' && rest.length >= 3 && rest[2] === 'heads' && rest.length === 4) {
        const branch = rest[3];
        const tip = branchTip(repo, branch);
        if (tip === null) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha: tip, type: 'commit' }, url: '' });
        return;
      }
      if (method === 'POST' && rest.length === 2) {
        const input = record(body) ?? {};
        const ref = typeof input.ref === 'string' ? input.ref : '';
        const sha = typeof input.sha === 'string' ? input.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || repo.objects.get(sha) === undefined) {
          sendJson(res, 422, { message: 'Invalid ref or sha' });
          return;
        }
        if (repo.refs.has(ref)) {
          sendJson(res, 422, { message: 'Reference already exists' });
          return;
        }
        repo.refs.set(ref, sha);
        repo.updatedAt = nowIso();
        sendJson(res, 201, { ref, object: { sha, type: 'commit' }, url: '' });
        return;
      }
      notFound(res);
      return;
    }

    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = (query.get('state') ?? 'open').toLowerCase();
          const sort = query.get('sort') ?? 'created';
          const direction = (query.get('direction') ?? 'desc').toLowerCase();
          let list = [...repo.issues.values()];
          if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
          if (sort === 'created') list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
          listWithPagination(req, res, path, query, list.map((issue) => issueJson(repo, issue)));
          return;
        }
        if (method === 'POST') {
          const input = record(body) ?? {};
          const title = typeof input.title === 'string' ? input.title : '';
          if (title === '') {
            sendJson(res, 422, { message: 'Title is required' });
            return;
          }
          const labelNames = Array.isArray(input.labels) ? input.labels.filter((entry): entry is string => typeof entry === 'string') : [];
          const attached: Label[] = [];
          for (const labelName of labelNames) {
            const found = [...repo.labels.values()].find((label) => label.name.toLowerCase() === labelName.toLowerCase());
            if (found === undefined) {
              sendJson(res, 422, { message: `Label does not exist: ${labelName}` });
              return;
            }
            attached.push(found);
          }
          repo.seq += 1;
          const issue: Issue = {
            id: globalIdSeq,
            number: repo.seq,
            title,
            body: typeof input.body === 'string' ? input.body : '',
            state: 'open',
            labels: attached,
            createdAt: nowIso(),
            updatedAt: nowIso(),
            closedAt: null,
          };
          globalIdSeq += 1;
          repo.issues.set(issue.number, issue);
          repo.comments.set(issue.number, []);
          sendJson(res, 201, issueJson(repo, issue));
          return;
        }
      }
      const number = Number(rest[1]);
      if (!Number.isInteger(number) || number < 1) {
        notFound(res);
        return;
      }
      const issue = repo.issues.get(number);
      if (rest.length === 2) {
        if (issue === undefined) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
        if (method === 'PATCH') {
          const input = record(body) ?? {};
          if (typeof input.title === 'string') issue.title = input.title;
          if (typeof input.body === 'string') issue.body = input.body;
          if (typeof input.state === 'string' && (input.state === 'open' || input.state === 'closed')) {
            issue.state = input.state;
            issue.closedAt = input.state === 'closed' ? nowIso() : null;
          }
          if (Array.isArray(input.labels)) {
            const attached: Label[] = [];
            for (const labelName of input.labels.filter((entry): entry is string => typeof entry === 'string')) {
              const found = [...repo.labels.values()].find((label) => label.name.toLowerCase() === labelName.toLowerCase());
              if (found === undefined) {
                sendJson(res, 422, { message: `Label does not exist: ${labelName}` });
                return;
              }
              attached.push(found);
            }
            issue.labels = attached;
          }
          issue.updatedAt = nowIso();
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
        notFound(res);
        return;
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (issue === undefined) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        if (method === 'GET') {
          const list = (repo.comments.get(number) ?? []).map((comment) => ({
            id: comment.id,
            node_id: commentGlobalId(repo, number, comment),
            body: comment.body,
            user: userJson(),
            created_at: comment.createdAt,
            updated_at: comment.updatedAt,
            html_url: '',
            url: '',
          }));
          sendJson(res, 200, list);
          return;
        }
        if (method === 'POST') {
          const input = record(body) ?? {};
          const text = typeof input.body === 'string' ? input.body : '';
          if (text === '') {
            sendJson(res, 422, { message: 'Comment body is required' });
            return;
          }
          const comment: Comment = { id: globalIdSeq, body: text, createdAt: nowIso(), updatedAt: nowIso() };
          globalIdSeq += 1;
          const list = repo.comments.get(number) ?? [];
          list.push(comment);
          repo.comments.set(number, list);
          sendJson(res, 201, {
            id: comment.id,
            node_id: commentGlobalId(repo, number, comment),
            body: comment.body,
            user: userJson(),
            created_at: comment.createdAt,
            updated_at: comment.updatedAt,
            html_url: '',
            url: '',
          });
          return;
        }
        notFound(res);
        return;
      }
      notFound(res);
      return;
    }

    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = (query.get('state') ?? 'open').toLowerCase();
          let list = [...repo.pulls.values()];
          if (state === 'open' || state === 'closed') list = list.filter((pull) => pull.state === state);
          list.sort((a, b) => b.number - a.number);
          listWithPagination(req, res, path, query, list.map((pull) => pullJson(repo, pull)));
          return;
        }
        if (method === 'POST') {
          const input = record(body) ?? {};
          const title = typeof input.title === 'string' ? input.title : '';
          const headRaw = typeof input.head === 'string' ? input.head : '';
          const baseRaw = typeof input.base === 'string' ? input.base : '';
          const head = headRaw.includes(':') ? (headRaw.split(':').pop() as string) : headRaw;
          const base = baseRaw.includes(':') ? (baseRaw.split(':').pop() as string) : baseRaw;
          if (title === '' || head === '' || base === '') {
            sendJson(res, 422, { message: 'title, head and base are required' });
            return;
          }
          const headSha = branchTip(repo, head);
          const baseSha = branchTip(repo, base);
          if (headSha === null || baseSha === null) {
            sendJson(res, 422, { message: 'head or base branch does not exist' });
            return;
          }
          const duplicate = [...repo.pulls.values()].find((pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base);
          if (duplicate !== undefined) {
            sendJson(res, 422, { message: 'A pull request already exists for this head branch' });
            return;
          }
          repo.seq += 1;
          const pull: Pull = {
            id: globalIdSeq,
            number: repo.seq,
            title,
            body: typeof input.body === 'string' ? input.body : '',
            state: 'open',
            headRef: head,
            baseRef: base,
            headSha,
            baseSha,
            merged: false,
            mergedAt: null,
            mergeCommitSha: null,
            createdAt: nowIso(),
            updatedAt: nowIso(),
          };
          globalIdSeq += 1;
          repo.pulls.set(pull.number, pull);
          sendJson(res, 201, pullJson(repo, pull));
          return;
        }
      }
      const number = Number(rest[1]);
      if (!Number.isInteger(number) || number < 1) {
        notFound(res);
        return;
      }
      const pull = repo.pulls.get(number);
      if (rest.length === 2) {
        if (pull === undefined) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, pullJson(repo, pull));
          return;
        }
        notFound(res);
        return;
      }
      if (rest.length === 3 && rest[2] === 'files') {
        if (pull === undefined) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        if (method === 'GET') {
          const headFiles = treeFileMap(repo, parseCommit((repo.objects.get(pull.headSha) as GitObject).data).tree);
          const files = pullFiles(repo, pull).map((file) => ({
            sha: headFiles.get(file.filename) ?? '',
            filename: file.filename,
            status: file.status,
            additions: file.additions,
            deletions: file.deletions,
            changes: file.changes,
            blob_url: '',
            raw_url: '',
            contents_url: '',
            patch: '',
          }));
          sendJson(res, 200, files);
          return;
        }
        notFound(res);
        return;
      }
      if (rest.length === 3 && rest[2] === 'merge') {
        if (pull === undefined) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        if (method === 'PUT') {
          if (pull.state !== 'open') {
            sendJson(res, 405, { message: 'Pull request is already closed' });
            return;
          }
          if (pullConflicts(repo, pull)) {
            sendJson(res, 405, { message: 'Merge conflict' });
            return;
          }
          const input = record(body) ?? {};
          const commitMessage = typeof input.commit_message === 'string' ? input.commit_message : '';
          const mergeOid = squashMerge(repo, pull, commitMessage);
          if (mergeOid === null) {
            sendJson(res, 405, { message: 'Merge conflict' });
            return;
          }
          sendJson(res, 200, { sha: mergeOid, merged: true, message: 'Pull request successfully merged' });
          return;
        }
        notFound(res);
        return;
      }
      notFound(res);
      return;
    }

    notFound(res);
    return;
  }

  notFound(res);
}

// ---------------------------------------------------------------------------
// Shared cores used by both REST-adjacent surfaces (GraphQL, MCP)
// ---------------------------------------------------------------------------

function createIssueCore(repo: Repo, title: string, bodyText: string, labels: readonly Label[] = []): Issue {
  repo.seq += 1;
  const issue: Issue = {
    id: globalIdSeq,
    number: repo.seq,
    title,
    body: bodyText,
    state: 'open',
    labels: [...labels],
    createdAt: nowIso(),
    updatedAt: nowIso(),
    closedAt: null,
  };
  globalIdSeq += 1;
  repo.issues.set(issue.number, issue);
  repo.comments.set(issue.number, []);
  return issue;
}

function createPullCore(repo: Repo, title: string, bodyText: string, head: string, base: string): { pull: Pull } | { error: string } {
  const headSha = branchTip(repo, head);
  const baseSha = branchTip(repo, base);
  if (headSha === null || baseSha === null) return { error: 'head or base branch does not exist' };
  const duplicate = [...repo.pulls.values()].find((pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base);
  if (duplicate !== undefined) return { error: 'A pull request already exists for this head branch' };
  repo.seq += 1;
  const pull: Pull = {
    id: globalIdSeq,
    number: repo.seq,
    title,
    body: bodyText,
    state: 'open',
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  globalIdSeq += 1;
  repo.pulls.set(pull.number, pull);
  return { pull };
}

function addCommentCore(repo: Repo, issueNumber: number, text: string): Comment | null {
  const issue = repo.issues.get(issueNumber);
  if (issue === undefined) return null;
  const comment: Comment = { id: globalIdSeq, body: text, createdAt: nowIso(), updatedAt: nowIso() };
  globalIdSeq += 1;
  const list = repo.comments.get(issueNumber) ?? [];
  list.push(comment);
  repo.comments.set(issueNumber, list);
  return comment;
}

// ---------------------------------------------------------------------------
// GraphQL v4: a small executor for the documents gh and github-mcp-server send
// ---------------------------------------------------------------------------

interface GqlSelection {
  alias: string;
  name: string;
  args: Record<string, unknown>;
  selections: GqlSelection[];
  fragmentOn: string | null;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  selections: GqlSelection[];
}

type GqlToken =
  | { kind: 'brace'; value: '{' | '}' }
  | { kind: 'paren'; value: '(' | ')' }
  | { kind: 'bracket'; value: '[' | ']' }
  | { kind: 'colon' | 'comma' | 'dollar' | 'bang' | 'at' }
  | { kind: 'ellipsis' }
  | { kind: 'name'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'number'; value: number };

function tokenizeGql(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r' || char === ',') {
      index += 1;
      continue;
    }
    if (char === '#') {
      while (index < source.length && source[index] !== '\n') index += 1;
      continue;
    }
    if (char === '{' || char === '}') {
      tokens.push({ kind: 'brace', value: char });
      index += 1;
      continue;
    }
    if (char === '(' || char === ')') {
      tokens.push({ kind: 'paren', value: char });
      index += 1;
      continue;
    }
    if (char === '[' || char === ']') {
      tokens.push({ kind: 'bracket', value: char });
      index += 1;
      continue;
    }
    if (char === ':') {
      tokens.push({ kind: 'colon' });
      index += 1;
      continue;
    }
    if (char === '$') {
      tokens.push({ kind: 'dollar' });
      index += 1;
      continue;
    }
    if (char === '!') {
      tokens.push({ kind: 'bang' });
      index += 1;
      continue;
    }
    if (char === '@') {
      tokens.push({ kind: 'at' });
      index += 1;
      continue;
    }
    if (source.startsWith('...', index)) {
      tokens.push({ kind: 'ellipsis' });
      index += 3;
      continue;
    }
    if (char === '"') {
      let value = '';
      index += 1;
      while (index < source.length && source[index] !== '"') {
        if (source[index] === '\\' && index + 1 < source.length) {
          const next = source[index + 1];
          value += next === 'n' ? '\n' : next === 't' ? '\t' : next === 'r' ? '\r' : next;
          index += 2;
        } else {
          value += source[index];
          index += 1;
        }
      }
      index += 1;
      tokens.push({ kind: 'string', value });
      continue;
    }
    if (/[0-9-]/.test(char)) {
      const match = /^-?\d+(\.\d+)?/.exec(source.slice(index));
      if (match !== null) {
        tokens.push({ kind: 'number', value: Number(match[0]) });
        index += match[0].length;
        continue;
      }
    }
    if (/[A-Za-z_]/.test(char)) {
      const match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(source.slice(index));
      if (match !== null) {
        tokens.push({ kind: 'name', value: match[0] });
        index += match[0].length;
        continue;
      }
    }
    index += 1;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];

  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }

  private next(): GqlToken | undefined {
    return this.tokens[this.pos++];
  }

  private expectName(): string {
    const token = this.next();
    if (token !== undefined && token.kind === 'name') return token.value;
    throw new Error('expected a name in the GraphQL document');
  }

  parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    const first = this.peek();
    if (first !== undefined && first.kind === 'name' && (first.value === 'query' || first.value === 'mutation')) {
      kind = first.value;
      this.next();
      const after = this.peek();
      if (after !== undefined && after.kind === 'name') this.next();
    }
    // Variable definitions, if any: ($name: Type, ...).
    const open = this.peek();
    if (open !== undefined && open.kind === 'paren' && open.value === '(') {
      this.next();
      let depth = 1;
      while (depth > 0) {
        const token = this.next();
        if (token === undefined) break;
        if (token.kind === 'paren' && token.value === '(') depth += 1;
        else if (token.kind === 'paren' && token.value === ')') depth -= 1;
      }
    }
    const selections = this.parseSelectionSet();
    return { kind, selections };
  }

  private parseSelectionSet(): GqlSelection[] {
    const open = this.next();
    if (open === undefined || open.kind !== 'brace' || open.value !== '{') throw new Error('expected { in the GraphQL document');
    const selections: GqlSelection[] = [];
    for (;;) {
      const token = this.peek();
      if (token === undefined) throw new Error('unterminated selection set');
      if (token.kind === 'brace' && token.value === '}') {
        this.next();
        return selections;
      }
      selections.push(this.parseSelection());
    }
  }

  private parseSelection(): GqlSelection {
    const token = this.peek();
    if (token !== undefined && token.kind === 'ellipsis') {
      this.next();
      const next = this.peek();
      if (next !== undefined && next.kind === 'name' && next.value === 'on') {
        this.next();
        const typeName = this.expectName();
        const selections = this.parseSelectionSet();
        return { alias: '', name: '', args: {}, selections, fragmentOn: typeName };
      }
      throw new Error('named fragments are not supported');
    }
    const name = this.expectName();
    let alias = name;
    let fieldName = name;
    const colon = this.peek();
    if (colon !== undefined && colon.kind === 'colon') {
      this.next();
      fieldName = this.expectName();
      alias = name;
    }
    const args: Record<string, unknown> = {};
    const paren = this.peek();
    if (paren !== undefined && paren.kind === 'paren' && paren.value === '(') {
      this.next();
      for (;;) {
        const next = this.peek();
        if (next === undefined) throw new Error('unterminated arguments');
        if (next.kind === 'paren' && next.value === ')') {
          this.next();
          break;
        }
        const argName = this.expectName();
        const colonToken = this.next();
        if (colonToken === undefined || colonToken.kind !== 'colon') throw new Error('expected : in arguments');
        args[argName] = this.parseValue();
      }
    }
    // Directives, if any: @name(...) — skipped.
    for (;;) {
      const next = this.peek();
      if (next !== undefined && next.kind === 'at') {
        this.next();
        this.expectName();
        const maybeParen = this.peek();
        if (maybeParen !== undefined && maybeParen.kind === 'paren' && maybeParen.value === '(') {
          this.next();
          let depth = 1;
          while (depth > 0) {
            const token = this.next();
            if (token === undefined) break;
            if (token.kind === 'paren' && token.value === '(') depth += 1;
            else if (token.kind === 'paren' && token.value === ')') depth -= 1;
          }
        }
        continue;
      }
      break;
    }
    let selections: GqlSelection[] = [];
    const brace = this.peek();
    if (brace !== undefined && brace.kind === 'brace' && brace.value === '{') selections = this.parseSelectionSet();
    return { alias, name: fieldName, args, selections, fragmentOn: null };
  }

  private parseValue(): unknown {
    const token = this.next();
    if (token === undefined) throw new Error('expected a value');
    if (token.kind === 'dollar') return { __variable: this.expectName() };
    if (token.kind === 'string') return token.value;
    if (token.kind === 'number') return token.value;
    if (token.kind === 'name') {
      if (token.value === 'true') return true;
      if (token.value === 'false') return false;
      if (token.value === 'null') return null;
      return { __enum: token.value };
    }
    if (token.kind === 'bracket' && token.value === '[') {
      const items: unknown[] = [];
      for (;;) {
        const next = this.peek();
        if (next === undefined) throw new Error('unterminated list');
        if (next.kind === 'bracket' && next.value === ']') {
          this.next();
          return items;
        }
        items.push(this.parseValue());
      }
    }
    if (token.kind === 'brace' && token.value === '{') {
      const object: Record<string, unknown> = {};
      for (;;) {
        const next = this.peek();
        if (next === undefined) throw new Error('unterminated object');
        if (next.kind === 'brace' && next.value === '}') {
          this.next();
          return object;
        }
        const key = this.expectName();
        const colonToken = this.next();
        if (colonToken === undefined || colonToken.kind !== 'colon') throw new Error('expected : in object value');
        object[key] = this.parseValue();
      }
    }
    throw new Error('unexpected token in value');
  }
}

function resolveVariables(value: unknown, variables: Record<string, unknown>): unknown {
  if (value !== null && typeof value === 'object') {
    if (Array.isArray(value)) return value.map((entry) => resolveVariables(entry, variables));
    const record = value as Record<string, unknown>;
    if (typeof record.__variable === 'string') return variables[record.__variable] ?? null;
    if (typeof record.__enum === 'string') return record.__enum;
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(record)) out[key] = resolveVariables(entry, variables);
    return out;
  }
  return value;
}

function resolveArgs(args: Record<string, unknown>, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) out[key] = resolveVariables(value, variables);
  return out;
}

// The schema the introspection probes describe.
const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'closedAt', 'author', 'labels', 'comments', 'closed', 'locked', 'repository'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'mergeable', 'merged', 'mergeCommit', 'mergedAt', 'createdAt', 'updatedAt', 'files', 'author', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt', 'updatedAt', 'isPrivate', 'fork'],
  SearchType: [],
  CreateIssuePayload: ['issue'],
  CloseIssuePayload: ['issue'],
  CreatePullRequestPayload: ['pullRequest'],
  MergePullRequestPayload: ['pullRequest'],
  AddCommentPayload: ['commentEdge'],
  CommentEdge: ['node'],
  Comment: ['id', 'body'],
};
const GQL_SEARCH_ENUMS = ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'TOPIC', 'PACKAGE', 'MARKETPLACE_LISTING'];

type GqlSource = Record<string, unknown>;

function gqlCursor(number: number): string {
  return Buffer.from(`cursor:${number}`, 'utf8').toString('base64url');
}

function gqlCursorNumber(cursor: string | undefined): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  try {
    const text = Buffer.from(cursor, 'base64url').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? null : Number(match[1]);
  } catch {
    return null;
  }
}

function issuesConnection(repo: Repo, args: Record<string, unknown>): GqlSource {
  const first = typeof args.first === 'number' ? args.first : 10;
  const after = gqlCursorNumber(typeof args.after === 'string' ? args.after : undefined);
  const states = Array.isArray(args.states) ? (args.states as string[]) : null;
  const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
  const direction = orderBy.direction === 'ASC' ? 'ASC' : 'DESC';
  let list = [...repo.issues.values()];
  if (states !== null) {
    const wanted = new Set(states.map((state) => String(state).toLowerCase()));
    list = list.filter((issue) => wanted.has(issue.state));
  }
  list.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
  if (after !== null) {
    const index = list.findIndex((issue) => issue.number === after);
    list = index < 0 ? list : list.slice(index + 1);
  }
  const page = list.slice(0, Math.max(0, first));
  const hasNext = list.length > page.length;
  const endCursor = page.length > 0 ? gqlCursor(page[page.length - 1].number) : null;
  return {
    __typename: 'IssueConnection',
    nodes: page.map((issue) => ({ __typename: 'Issue', repo, issue })),
    pageInfo: { __typename: 'PageInfo', hasNextPage: hasNext, hasPreviousPage: after !== null, startCursor: page.length > 0 ? gqlCursor(page[0].number) : null, endCursor },
    totalCount: list.length,
  };
}

function pullsConnection(repo: Repo, args: Record<string, unknown>): GqlSource {
  const first = typeof args.first === 'number' ? args.first : 10;
  const states = Array.isArray(args.states) ? (args.states as string[]) : null;
  let list = [...repo.pulls.values()];
  if (states !== null) {
    const wanted = new Set(states.map((state) => String(state).toLowerCase()));
    list = list.filter((pull) => wanted.has(pull.state));
  } else {
    list = list.filter((pull) => pull.state === 'open');
  }
  list.sort((a, b) => b.number - a.number);
  const page = list.slice(0, Math.max(0, first));
  return {
    __typename: 'PullRequestConnection',
    nodes: page.map((pull) => ({ __typename: 'PullRequest', repo, pull })),
    pageInfo: { __typename: 'PageInfo', hasNextPage: list.length > page.length, hasPreviousPage: false, startCursor: null, endCursor: null },
    totalCount: list.length,
  };
}

function fieldValue(typeName: string, source: GqlSource, field: string, args: Record<string, unknown>): { found: boolean; value: unknown; returnType: string } {
  const repo = source.repo as Repo | undefined;
  const issue = source.issue as Issue | undefined;
  const pull = source.pull as Pull | undefined;
  const notFound = { found: false, value: null, returnType: '' };
  switch (typeName) {
    case 'Query': {
      if (field === 'viewer') return { found: true, value: { __typename: 'User', login: VIEWER.login }, returnType: 'User' };
      if (field === 'repository') {
        const owner = typeof args.owner === 'string' ? args.owner : '';
        const name = typeof args.name === 'string' ? args.name : '';
        const found = owner.toLowerCase() === VIEWER.login.toLowerCase() ? findRepo(owner, name) : undefined;
        if (found === undefined) return { found: true, value: null, returnType: 'Repository' };
        return { found: true, value: { __typename: 'Repository', repo: found }, returnType: 'Repository' };
      }
      if (field === 'node') {
        const id = typeof args.id === 'string' ? args.id : '';
        const decoded = decodeGlobalId(id);
        if (decoded === null) return { found: true, value: null, returnType: 'Node' };
        if (decoded.kind === 'repo') {
          const slash = decoded.key.indexOf('/');
          if (slash < 0) return { found: true, value: null, returnType: 'Node' };
          const found = findRepo(decoded.key.slice(0, slash), decoded.key.slice(slash + 1));
          if (found === undefined) return { found: true, value: null, returnType: 'Node' };
          return { found: true, value: { __typename: 'Repository', repo: found }, returnType: 'Repository' };
        }
        if (decoded.kind === 'issue' || decoded.kind === 'pull') {
          const hash = decoded.key.indexOf('#');
          if (hash < 0) return { found: true, value: null, returnType: 'Node' };
          const ownerName = decoded.key.slice(0, hash);
          const slash = ownerName.indexOf('/');
          if (slash < 0) return { found: true, value: null, returnType: 'Node' };
          const found = findRepo(ownerName.slice(0, slash), ownerName.slice(slash + 1));
          if (found === undefined) return { found: true, value: null, returnType: 'Node' };
          const number = Number(decoded.key.slice(hash + 1));
          if (decoded.kind === 'issue') {
            const foundIssue = found.issues.get(number);
            if (foundIssue === undefined) return { found: true, value: null, returnType: 'Node' };
            return { found: true, value: { __typename: 'Issue', repo: found, issue: foundIssue }, returnType: 'Issue' };
          }
          const foundPull = found.pulls.get(number);
          if (foundPull === undefined) return { found: true, value: null, returnType: 'Node' };
          return { found: true, value: { __typename: 'PullRequest', repo: found, pull: foundPull }, returnType: 'PullRequest' };
        }
        return { found: true, value: null, returnType: 'Node' };
      }
      if (field === '__type') {
        const name = typeof args.name === 'string' ? args.name : '';
        const fields = GQL_TYPE_FIELDS[name];
        if (fields === undefined && name !== 'SearchType') return { found: true, value: null, returnType: '__Type' };
        if (name === 'SearchType') {
          return { found: true, value: { __typename: '__Type', name, kind: 'ENUM', fields: [] as string[], enumValues: GQL_SEARCH_ENUMS }, returnType: '__Type' };
        }
        return { found: true, value: { __typename: '__Type', name, kind: 'OBJECT', fields: fields ?? [], enumValues: [] as string[] }, returnType: '__Type' };
      }
      if (field === '__schema') {
        return { found: true, value: { __typename: '__Schema', types: Object.keys(GQL_TYPE_FIELDS).map((name) => ({ name })) }, returnType: '__Schema' };
      }
      return notFound;
    }
    case 'User': {
      if (field === 'login') return { found: true, value: source.login ?? VIEWER.login, returnType: 'String' };
      if (field === 'id') return { found: true, value: globalId('user', String(source.login ?? VIEWER.login)), returnType: 'ID' };
      if (field === 'name') return { found: true, value: VIEWER.name, returnType: 'String' };
      if (field === 'email') return { found: true, value: VIEWER.email, returnType: 'String' };
      return notFound;
    }
    case 'Repository': {
      if (repo === undefined) return notFound;
      if (field === 'id') return { found: true, value: repoGlobalId(repo), returnType: 'ID' };
      if (field === 'databaseId') return { found: true, value: repo.id, returnType: 'Int' };
      if (field === 'name') return { found: true, value: repo.name, returnType: 'String' };
      if (field === 'nameWithOwner') return { found: true, value: `${repo.owner}/${repo.name}`, returnType: 'String' };
      if (field === 'owner') return { found: true, value: { __typename: 'User', login: repo.owner }, returnType: 'User' };
      if (field === 'description') return { found: true, value: repo.description, returnType: 'String' };
      if (field === 'defaultBranchRef') {
        const tip = branchTip(repo, repo.defaultBranch);
        if (tip === null) return { found: true, value: null, returnType: 'Ref' };
        return { found: true, value: { __typename: 'Ref', name: repo.defaultBranch, target: tip }, returnType: 'Ref' };
      }
      if (field === 'viewerPermission') return { found: true, value: 'ADMIN', returnType: 'String' };
      if (field === 'hasIssuesEnabled') return { found: true, value: true, returnType: 'Boolean' };
      if (field === 'isPrivate') return { found: true, value: repo.private, returnType: 'Boolean' };
      if (field === 'url') return { found: true, value: '', returnType: 'String' };
      if (field === 'createdAt') return { found: true, value: repo.createdAt, returnType: 'String' };
      if (field === 'updatedAt') return { found: true, value: repo.updatedAt, returnType: 'String' };
      if (field === 'issue') {
        const number = typeof args.number === 'number' ? args.number : -1;
        const found = repo.issues.get(number);
        if (found === undefined) return { found: true, value: null, returnType: 'Issue' };
        return { found: true, value: { __typename: 'Issue', repo, issue: found }, returnType: 'Issue' };
      }
      if (field === 'issues') return { found: true, value: issuesConnection(repo, args), returnType: 'IssueConnection' };
      if (field === 'pullRequest') {
        const number = typeof args.number === 'number' ? args.number : -1;
        const found = repo.pulls.get(number);
        if (found === undefined) return { found: true, value: null, returnType: 'PullRequest' };
        return { found: true, value: { __typename: 'PullRequest', repo, pull: found }, returnType: 'PullRequest' };
      }
      if (field === 'pullRequests') return { found: true, value: pullsConnection(repo, args), returnType: 'PullRequestConnection' };
      return notFound;
    }
    case 'Issue': {
      if (issue === undefined) return notFound;
      if (field === 'id') return { found: true, value: issueGlobalId(repo as Repo, issue), returnType: 'ID' };
      if (field === 'number') return { found: true, value: issue.number, returnType: 'Int' };
      if (field === 'title') return { found: true, value: issue.title, returnType: 'String' };
      if (field === 'state') return { found: true, value: issue.state.toUpperCase(), returnType: 'String' };
      if (field === 'body') return { found: true, value: issue.body, returnType: 'String' };
      if (field === 'url') return { found: true, value: '', returnType: 'String' };
      if (field === 'createdAt') return { found: true, value: issue.createdAt, returnType: 'String' };
      if (field === 'updatedAt') return { found: true, value: issue.updatedAt, returnType: 'String' };
      if (field === 'closedAt') return { found: true, value: issue.closedAt, returnType: 'String' };
      if (field === 'closed') return { found: true, value: issue.state === 'closed', returnType: 'Boolean' };
      if (field === 'author') return { found: true, value: { __typename: 'User', login: VIEWER.login }, returnType: 'User' };
      if (field === 'repository') return { found: true, value: { __typename: 'Repository', repo: repo as Repo }, returnType: 'Repository' };
      if (field === 'labels') return { found: true, value: { __typename: 'LabelConnection', nodes: issue.labels.map((label) => ({ __typename: 'Label', name: label.name })) }, returnType: 'LabelConnection' };
      return notFound;
    }
    case 'PullRequest': {
      if (pull === undefined) return notFound;
      if (field === 'id') return { found: true, value: pullGlobalId(repo as Repo, pull), returnType: 'ID' };
      if (field === 'number') return { found: true, value: pull.number, returnType: 'Int' };
      if (field === 'title') return { found: true, value: pull.title, returnType: 'String' };
      if (field === 'body') return { found: true, value: pull.body, returnType: 'String' };
      if (field === 'state') return { found: true, value: pull.state.toUpperCase(), returnType: 'String' };
      if (field === 'headRefName') return { found: true, value: pull.headRef, returnType: 'String' };
      if (field === 'baseRefName') return { found: true, value: pull.baseRef, returnType: 'String' };
      if (field === 'headRefOid') return { found: true, value: pull.headSha, returnType: 'String' };
      if (field === 'baseRefOid') return { found: true, value: pull.baseSha, returnType: 'String' };
      if (field === 'mergeable') return { found: true, value: pullMergeable(repo as Repo, pull), returnType: 'String' };
      if (field === 'merged') return { found: true, value: pull.merged, returnType: 'Boolean' };
      if (field === 'mergedAt') return { found: true, value: pull.mergedAt, returnType: 'String' };
      if (field === 'createdAt') return { found: true, value: pull.createdAt, returnType: 'String' };
      if (field === 'updatedAt') return { found: true, value: pull.updatedAt, returnType: 'String' };
      if (field === 'url') return { found: true, value: '', returnType: 'String' };
      if (field === 'author') return { found: true, value: { __typename: 'User', login: VIEWER.login }, returnType: 'User' };
      if (field === 'files') {
        const files = pullFiles(repo as Repo, pull).map((file) => ({ __typename: 'PullRequestFile', path: file.filename }));
        const first = typeof args.first === 'number' ? args.first : 10;
        return {
          found: true,
          value: { __typename: 'PullRequestFileConnection', nodes: files.slice(0, first), pageInfo: { __typename: 'PageInfo', hasNextPage: files.length > first, endCursor: null } },
          returnType: 'PullRequestFileConnection',
        };
      }
      return notFound;
    }
    case 'Ref': {
      if (field === 'name') return { found: true, value: source.name ?? '', returnType: 'String' };
      if (field === 'target') {
        const oid = typeof source.target === 'string' ? source.target : '';
        return { found: true, value: { __typename: 'Commit', oid }, returnType: 'Commit' };
      }
      return notFound;
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'PullRequestFileConnection':
    case 'LabelConnection': {
      if (field === 'nodes') return { found: true, value: (source.nodes as unknown[]) ?? [], returnType: 'NodeList' };
      if (field === 'edges') return { found: true, value: [], returnType: 'NodeList' };
      if (field === 'pageInfo') return { found: true, value: source.pageInfo ?? { __typename: 'PageInfo', hasNextPage: false, endCursor: null }, returnType: 'PageInfo' };
      if (field === 'totalCount') return { found: true, value: typeof source.totalCount === 'number' ? source.totalCount : ((source.nodes as unknown[]) ?? []).length, returnType: 'Int' };
      return notFound;
    }
    case 'PageInfo': {
      if (field === 'hasNextPage') return { found: true, value: source.hasNextPage === true, returnType: 'Boolean' };
      if (field === 'hasPreviousPage') return { found: true, value: source.hasPreviousPage === true, returnType: 'Boolean' };
      if (field === 'endCursor') return { found: true, value: typeof source.endCursor === 'string' ? source.endCursor : null, returnType: 'String' };
      if (field === 'startCursor') return { found: true, value: typeof source.startCursor === 'string' ? source.startCursor : null, returnType: 'String' };
      return notFound;
    }
    case '__Type': {
      if (field === 'name') return { found: true, value: source.name ?? '', returnType: 'String' };
      if (field === 'kind') return { found: true, value: source.kind ?? 'OBJECT', returnType: 'String' };
      if (field === 'fields') {
        const names = (source.fields as string[]) ?? [];
        return { found: true, value: names.map((name) => ({ __typename: '__Field', name })), returnType: 'FieldList' };
      }
      if (field === 'enumValues') {
        const names = (source.enumValues as string[]) ?? [];
        return { found: true, value: names.map((name) => ({ __typename: '__EnumValue', name })), returnType: 'EnumList' };
      }
      if (field === 'description') return { found: true, value: null, returnType: 'String' };
      return notFound;
    }
    case '__Field':
    case '__EnumValue': {
      if (field === 'name') return { found: true, value: source.name ?? '', returnType: 'String' };
      return notFound;
    }
    case '__Schema': {
      if (field === 'types') return { found: true, value: (source.types as unknown[]) ?? [], returnType: 'TypeList' };
      if (field === 'queryType') return { found: true, value: { __typename: '__Type', name: 'Query', kind: 'OBJECT', fields: [] as string[], enumValues: [] as string[] }, returnType: '__Type' };
      if (field === 'mutationType') return { found: true, value: { __typename: '__Type', name: 'Mutation', kind: 'OBJECT', fields: [] as string[], enumValues: [] as string[] }, returnType: '__Type' };
      return notFound;
    }
    case 'Label': {
      if (field === 'name') return { found: true, value: source.name ?? '', returnType: 'String' };
      if (field === 'id') return { found: true, value: globalId('label', String(source.name ?? '')), returnType: 'ID' };
      return notFound;
    }
    case 'PullRequestFile': {
      if (field === 'path') return { found: true, value: source.path ?? '', returnType: 'String' };
      return notFound;
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      if (field === 'issue') return { found: true, value: source.issue ?? null, returnType: 'Issue' };
      return notFound;
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      if (field === 'pullRequest') return { found: true, value: source.pullRequest ?? null, returnType: 'PullRequest' };
      return notFound;
    }
    case 'AddCommentPayload': {
      if (field === 'commentEdge') return { found: true, value: source.commentEdge ?? null, returnType: 'CommentEdge' };
      return notFound;
    }
    case 'CommentEdge': {
      if (field === 'node') return { found: true, value: source.node ?? null, returnType: 'Comment' };
      return notFound;
    }
    case 'Comment': {
      if (field === 'id') return { found: true, value: source.id ?? '', returnType: 'ID' };
      if (field === 'body') return { found: true, value: source.body ?? '', returnType: 'String' };
      return notFound;
    }
    case 'Commit': {
      if (field === 'oid') return { found: true, value: source.oid ?? '', returnType: 'String' };
      if (field === 'id') return { found: true, value: source.oid ?? '', returnType: 'ID' };
      return notFound;
    }
    default:
      return notFound;
  }
}

function resolveSelectionSet(typeName: string, source: GqlSource, selections: GqlSelection[], variables: Record<string, unknown>, errors: Array<{ message: string }>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.fragmentOn !== null) {
      if (selection.fragmentOn === typeName || typeName === 'Node') {
        Object.assign(out, resolveSelectionSet(typeName, source, selection.selections, variables, errors));
      }
      continue;
    }
    const args = resolveArgs(selection.args, variables);
    const resolved = fieldValue(typeName, source, selection.name, args);
    if (!resolved.found) {
      errors.push({ message: `Cannot query field "${selection.name}" on type "${typeName}".` });
      continue;
    }
    const value = resolved.value;
    if (value === null || value === undefined) {
      out[selection.alias] = null;
      continue;
    }
    if (selection.selections.length === 0) {
      out[selection.alias] = value;
      continue;
    }
    if (Array.isArray(value)) {
      out[selection.alias] = value.map((entry) => {
        if (entry !== null && typeof entry === 'object') {
          const entryType = (entry as GqlSource).__typename as string | undefined;
          return resolveSelectionSet(entryType ?? resolved.returnType, entry as GqlSource, selection.selections, variables, errors);
        }
        return entry;
      });
      continue;
    }
    if (typeof value === 'object') {
      const entryType = (value as GqlSource).__typename as string | undefined;
      out[selection.alias] = resolveSelectionSet(entryType ?? resolved.returnType, value as GqlSource, selection.selections, variables, errors);
      continue;
    }
    out[selection.alias] = value;
  }
  return out;
}

function findRepoByGlobalId(id: string): Repo | undefined {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'repo') return undefined;
  const slash = decoded.key.indexOf('/');
  if (slash < 0) return undefined;
  return findRepo(decoded.key.slice(0, slash), decoded.key.slice(slash + 1));
}

function findIssueByGlobalId(id: string): { repo: Repo; issue: Issue } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'issue') return null;
  const hash = decoded.key.indexOf('#');
  if (hash < 0) return null;
  const ownerName = decoded.key.slice(0, hash);
  const slash = ownerName.indexOf('/');
  if (slash < 0) return null;
  const repo = findRepo(ownerName.slice(0, slash), ownerName.slice(slash + 1));
  if (repo === undefined) return null;
  const issue = repo.issues.get(Number(decoded.key.slice(hash + 1)));
  return issue === undefined ? null : { repo, issue };
}

function findPullByGlobalId(id: string): { repo: Repo; pull: Pull } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'pull') return null;
  const hash = decoded.key.indexOf('#');
  if (hash < 0) return null;
  const ownerName = decoded.key.slice(0, hash);
  const slash = ownerName.indexOf('/');
  if (slash < 0) return null;
  const repo = findRepo(ownerName.slice(0, slash), ownerName.slice(slash + 1));
  if (repo === undefined) return null;
  const pull = repo.pulls.get(Number(decoded.key.slice(hash + 1)));
  return pull === undefined ? null : { repo, pull };
}

function executeMutation(selection: GqlSelection, variables: Record<string, unknown>, errors: Array<{ message: string }>): Record<string, unknown> {
  const args = resolveArgs(selection.args, variables);
  const input = (args.input ?? {}) as Record<string, unknown>;
  if (selection.name === 'createIssue') {
    const repo = typeof input.repositoryId === 'string' ? findRepoByGlobalId(input.repositoryId) : undefined;
    if (repo === undefined) {
      errors.push({ message: 'Could not resolve to a Repository with the given id.' });
      return { [selection.alias]: null };
    }
    const title = typeof input.title === 'string' ? input.title : '';
    const issue = createIssueCore(repo, title, typeof input.body === 'string' ? input.body : '');
    const source: GqlSource = { __typename: 'Issue', repo, issue };
    return { [selection.alias]: resolveSelectionSet('CreateIssuePayload', { __typename: 'CreateIssuePayload', issue: source }, selection.selections, variables, errors) };
  }
  if (selection.name === 'closeIssue') {
    const found = typeof input.issueId === 'string' ? findIssueByGlobalId(input.issueId) : null;
    if (found === null) {
      errors.push({ message: 'Could not resolve to an Issue with the given id.' });
      return { [selection.alias]: null };
    }
    found.issue.state = 'closed';
    found.issue.closedAt = nowIso();
    found.issue.updatedAt = nowIso();
    const source: GqlSource = { __typename: 'Issue', repo: found.repo, issue: found.issue };
    return { [selection.alias]: resolveSelectionSet('CloseIssuePayload', { __typename: 'CloseIssuePayload', issue: source }, selection.selections, variables, errors) };
  }
  if (selection.name === 'createPullRequest') {
    const repo = typeof input.repositoryId === 'string' ? findRepoByGlobalId(input.repositoryId) : undefined;
    if (repo === undefined) {
      errors.push({ message: 'Could not resolve to a Repository with the given id.' });
      return { [selection.alias]: null };
    }
    const head = typeof input.headRefName === 'string' ? input.headRefName : '';
    const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
    const title = typeof input.title === 'string' ? input.title : '';
    const made = createPullCore(repo, title, typeof input.body === 'string' ? input.body : '', head, base);
    if ('error' in made) {
      errors.push({ message: made.error });
      return { [selection.alias]: null };
    }
    const source: GqlSource = { __typename: 'PullRequest', repo, pull: made.pull };
    return { [selection.alias]: resolveSelectionSet('CreatePullRequestPayload', { __typename: 'CreatePullRequestPayload', pullRequest: source }, selection.selections, variables, errors) };
  }
  if (selection.name === 'mergePullRequest') {
    const found = typeof input.pullRequestId === 'string' ? findPullByGlobalId(input.pullRequestId) : null;
    if (found === null) {
      errors.push({ message: 'Could not resolve to a PullRequest with the given id.' });
      return { [selection.alias]: null };
    }
    if (found.pull.state !== 'open') {
      errors.push({ message: 'Pull request is already closed.' });
      return { [selection.alias]: null };
    }
    if (pullConflicts(found.repo, found.pull)) {
      errors.push({ message: 'Merge conflict.' });
      return { [selection.alias]: null };
    }
    const merged = squashMerge(found.repo, found.pull, '');
    if (merged === null) {
      errors.push({ message: 'Merge conflict.' });
      return { [selection.alias]: null };
    }
    const source: GqlSource = { __typename: 'PullRequest', repo: found.repo, pull: found.pull };
    return { [selection.alias]: resolveSelectionSet('MergePullRequestPayload', { __typename: 'MergePullRequestPayload', pullRequest: source }, selection.selections, variables, errors) };
  }
  if (selection.name === 'addComment') {
    const found = typeof input.subjectId === 'string' ? findIssueByGlobalId(input.subjectId) : null;
    if (found === null) {
      errors.push({ message: 'Could not resolve to an Issue with the given id.' });
      return { [selection.alias]: null };
    }
    const text = typeof input.body === 'string' ? input.body : '';
    const comment = addCommentCore(found.repo, found.issue.number, text);
    if (comment === null) {
      errors.push({ message: 'Could not add a comment.' });
      return { [selection.alias]: null };
    }
    const node: GqlSource = { __typename: 'Comment', id: commentGlobalId(found.repo, found.issue.number, comment), body: comment.body };
    const edge: GqlSource = { __typename: 'CommentEdge', node };
    return { [selection.alias]: resolveSelectionSet('AddCommentPayload', { __typename: 'AddCommentPayload', commentEdge: edge }, selection.selections, variables, errors) };
  }
  errors.push({ message: `Cannot query field "${selection.name}" on type "Mutation".` });
  return { [selection.alias]: null };
}

function executeOperation(operation: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  const errors: Array<{ message: string }> = [];
  if (operation.kind === 'mutation') {
    const data: Record<string, unknown> = {};
    for (const selection of operation.selections) {
      if (selection.fragmentOn !== null) continue;
      Object.assign(data, executeMutation(selection, variables, errors));
    }
    return { data, errors };
  }
  const data = resolveSelectionSet('Query', { __typename: 'Query' }, operation.selections, variables, errors);
  return { data, errors };
}

function runGraphQL(query: string, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  try {
    const parser = new GqlParser(tokenizeGql(query));
    const operation = parser.parseOperation();
    return executeOperation(operation, variables);
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'Failed to parse the GraphQL document.' }] };
  }
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!authed(req)) {
    unauthorized(res);
    return;
  }
  const raw = await readBody(req);
  const parsed = parseJsonBody(raw);
  if (!parsed.ok) {
    badRequest(res, 'Invalid JSON body');
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    const record = entry !== null && typeof entry === 'object' && !Array.isArray(entry) ? (entry as Record<string, unknown>) : {};
    const query = typeof record.query === 'string' ? record.query : '';
    const variables = record.variables !== null && typeof record.variables === 'object' && !Array.isArray(record.variables) ? (record.variables as Record<string, unknown>) : {};
    const result = runGraphQL(query, variables);
    const out: Record<string, unknown> = { data: result.data };
    if (result.errors.length > 0) out.errors = result.errors;
    return out;
  };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, parsed.value.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(parsed.value));
}

// ---------------------------------------------------------------------------
// MCP over streamable HTTP (JSON-RPC 2.0, plain JSON answers)
// ---------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, { type: string; description: string }>;
  required: string[];
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    properties: {
      name: { type: 'string', description: 'The repository name.' },
      owner: { type: 'string', description: 'The owner login (the authenticated user).' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      full_name: { type: 'string', description: 'The owner/name of the repository.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The issue title.' },
      body: { type: 'string', description: 'The issue body.' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The pull request title.' },
      body: { type: 'string', description: 'The pull request body.' },
      head: { type: 'string', description: 'The head branch name.' },
      base: { type: 'string', description: 'The base branch name.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'integer', description: 'The pull request number.' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
  {
    name: 'get_issue',
    description: 'Read one issue by number.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      number: { type: 'integer', description: 'The issue number.' },
    },
    required: ['owner', 'repo', 'number'],
  },
  {
    name: 'list_repos',
    description: 'List the repositories owned by the authenticated user.',
    properties: {},
    required: [],
  },
];

function mcpToolJson(tool: McpToolDef): Record<string, unknown> {
  return {
    name: tool.name,
    description: tool.description,
    inputSchema: { type: 'object', properties: tool.properties, required: tool.required },
  };
}

function mcpRepoFromArgs(args: Record<string, unknown>): Repo | { error: string } {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let name = typeof args.repo === 'string' ? args.repo : '';
  if ((owner === '' || name === '') && typeof args.full_name === 'string') {
    const parts = (args.full_name as string).split('/');
    if (parts.length === 2) {
      owner = parts[0];
      name = parts[1];
    }
  }
  if (owner === '' || name === '') return { error: 'owner and repo are required' };
  if (owner.toLowerCase() !== VIEWER.login.toLowerCase()) return { error: 'Not Found' };
  const repo = findRepo(owner, name);
  if (repo === undefined) return { error: 'Not Found' };
  return repo;
}

function mcpToolResult(payload: unknown, isError: boolean): Record<string, unknown> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return { content: [{ type: 'text', text }], structuredContent: payload, isError };
}

function callMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (tool === undefined) return { __rpcError: -32601, __message: `Unknown tool: ${name}` };
  for (const required of tool.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return mcpToolResult(`Missing required argument: ${required}`, true);
    }
  }
  switch (name) {
    case 'create_repo': {
      const repoName = String(args.name);
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(repoName)) return mcpToolResult('Invalid repository name', true);
      if (findRepo(VIEWER.login, repoName) !== undefined) return mcpToolResult('Repository already exists', true);
      const repo = createRepo(
        repoName,
        args.private === true,
        typeof args.description === 'string' ? args.description : '',
        'main',
      );
      return mcpToolResult(repoJson(repo), false);
    }
    case 'get_repo': {
      const repo = mcpRepoFromArgs(args);
      if ('error' in repo) return mcpToolResult(repo.error, true);
      return mcpToolResult(repoJson(repo), false);
    }
    case 'create_issue': {
      const repo = mcpRepoFromArgs(args);
      if ('error' in repo) return mcpToolResult(repo.error, true);
      const issue = createIssueCore(repo, String(args.title), typeof args.body === 'string' ? args.body : '');
      return mcpToolResult(issueJson(repo, issue), false);
    }
    case 'list_issues': {
      const repo = mcpRepoFromArgs(args);
      if ('error' in repo) return mcpToolResult(repo.error, true);
      const state = typeof args.state === 'string' ? args.state.toLowerCase() : 'open';
      let list = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
      list.sort((a, b) => b.number - a.number);
      return mcpToolResult({ issues: list.map((issue) => issueJson(repo, issue)) }, false);
    }
    case 'create_pull_request': {
      const repo = mcpRepoFromArgs(args);
      if ('error' in repo) return mcpToolResult(repo.error, true);
      const head = String(args.head).includes(':') ? (String(args.head).split(':').pop() as string) : String(args.head);
      const base = String(args.base).includes(':') ? (String(args.base).split(':').pop() as string) : String(args.base);
      const made = createPullCore(repo, String(args.title), typeof args.body === 'string' ? args.body : '', head, base);
      if ('error' in made) return mcpToolResult(made.error, true);
      return mcpToolResult(pullJson(repo, made.pull), false);
    }
    case 'merge_pull_request': {
      const repo = mcpRepoFromArgs(args);
      if ('error' in repo) return mcpToolResult(repo.error, true);
      const number = typeof args.pull_number === 'number' ? args.pull_number : Number(args.pull_number);
      const pull = repo.pulls.get(number);
      if (pull === undefined) return mcpToolResult('Pull request not found', true);
      if (pull.state !== 'open') return mcpToolResult('Pull request is already closed', true);
      if (pullConflicts(repo, pull)) return mcpToolResult('Merge conflict', true);
      const merged = squashMerge(repo, pull, '');
      if (merged === null) return mcpToolResult('Merge conflict', true);
      return mcpToolResult({ merged: true, sha: merged, number: pull.number, state: 'closed' }, false);
    }
    case 'get_issue': {
      const repo = mcpRepoFromArgs(args);
      if ('error' in repo) return mcpToolResult(repo.error, true);
      const number = typeof args.number === 'number' ? args.number : Number(args.number);
      const issue = repo.issues.get(number);
      if (issue === undefined) return mcpToolResult('Issue not found', true);
      return mcpToolResult(issueJson(repo, issue), false);
    }
    case 'list_repos': {
      const mine = [...repos.values()].filter((repo) => repo.owner.toLowerCase() === VIEWER.login.toLowerCase());
      return mcpToolResult({ repositories: mine.map(repoJson) }, false);
    }
    default:
      return mcpToolResult(`Unknown tool: ${name}`, true);
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== 'POST') {
    if (req.method === 'DELETE') {
      res.writeHead(200, { 'x-github-request-id': nextRequestId() });
      res.end();
      return;
    }
    sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  if (!authed(req)) {
    unauthorized(res);
    return;
  }
  const raw = await readBody(req);
  const parsed = parseJsonBody(raw);
  if (!parsed.ok) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const request = parsed.value;
  if (request === null || typeof request !== 'object' || Array.isArray(request)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const record = request as Record<string, unknown>;
  const id = record.id === undefined ? null : record.id;
  const method = typeof record.method === 'string' ? record.method : '';
  const params = record.params !== null && typeof record.params === 'object' && !Array.isArray(record.params) ? (record.params as Record<string, unknown>) : {};
  const result = (value: unknown): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: value });
  };
  const rpcError = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };
  if (method === '') {
    // A notification (no method, no id) is answered with 202 and no body.
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  if (method.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  if (method === 'server/discover') {
    result({
      supportedVersions: ['2026-07-28', '2025-11-25'],
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
      instructions: 'A GitHub-compatible git forge: repositories, issues, pull requests, git smart HTTP, GraphQL and MCP.',
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: FORGE_NAME, version: FORGE_VERSION } },
    });
    return;
  }
  if (method === 'initialize') {
    const asked = (params.protocolVersion as string | undefined) ?? '';
    const negotiated = /^\d{4}-\d{2}-\d{2}$/.test(asked) ? asked : '2026-07-28';
    result({
      protocolVersion: negotiated,
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
    });
    return;
  }
  if (method === 'ping') {
    result({});
    return;
  }
  if (method === 'tools/list') {
    result({ tools: MCP_TOOLS.map(mcpToolJson) });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = params.arguments !== null && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const outcome = callMcpTool(toolName, args);
    if ('__rpcError' in outcome) {
      rpcError(outcome.__rpcError as number, String(outcome.__message ?? 'Unknown tool'));
      return;
    }
    result(outcome);
    return;
  }
  rpcError(-32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const path = pathOf(req);
        const method = req.method ?? 'GET';
        const query = queryOf(req);

        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        const gitMatch = /^\/([^/]+)\/([^/]+)\.git(?:\/(.*))?$/.exec(path);
        if (gitMatch !== null) {
          if (!authed(req)) {
            unauthorized(res);
            return;
          }
          const owner = decodeSegment(gitMatch[1]);
          const repoName = decodeSegment(gitMatch[2]);
          const suffix = gitMatch[3] ?? '';
          const repo = owner.toLowerCase() === VIEWER.login.toLowerCase() ? findRepo(owner, repoName) : undefined;
          if (repo === undefined) {
            sendJson(res, 404, { message: 'Not Found' });
            return;
          }
          if (method === 'GET' && suffix === 'info/refs') {
            const service = query.get('service');
            if (service === 'git-upload-pack' || service === 'git-receive-pack') {
              handleInfoRefs(req, res, repo, service);
              return;
            }
            notFound(res);
            return;
          }
          if (method === 'POST' && suffix === 'git-upload-pack') {
            await handleUploadPack(req, res, repo);
            return;
          }
          if (method === 'POST' && suffix === 'git-receive-pack') {
            await handleReceivePack(req, res, repo);
            return;
          }
          notFound(res);
          return;
        }

        if (path === '/api/graphql') {
          if (method === 'POST') {
            await handleGraphQL(req, res);
            return;
          }
          notFound(res);
          return;
        }

        if (path === '/mcp') {
          await handleMcp(req, res);
          return;
        }

        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          await handleRest(req, res, path, method, query);
          return;
        }

        notFound(res);
      } catch (err) {
        if (!res.headersSent) {
          sendJson(res, 500, { message: err instanceof Error ? err.message : 'Internal Server Error' });
        } else {
          res.destroy();
        }
      }
    })();
  });
}
