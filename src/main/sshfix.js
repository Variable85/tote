/* Remote spaces, pure half: shell quoting, the commands we run over ssh, and
 * the detectors that read ssh's and Tailscale's output.
 *
 * Pure: no fs, no child_process, no electron -- so `node scripts/test-remote.js`
 * can cover the two things that would otherwise only be testable by breaking a
 * live connection: what exactly we send to a remote shell, and what we conclude
 * from what comes back. The impure half (spawning ssh, holding the control
 * socket, the state machine) lives in remote.js.
 *
 * Every remote path crosses a shell, so quoting has exactly one owner: shq()
 * here, applied once, by the command builders here. Nothing else in the app
 * ever concatenates a path into a remote command string.
 */
const path = require('path');

const stripAnsi = (s) => String(s).replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');

/* ----- quoting ----- */

// Single-quote a word for a POSIX shell: end the quote, escape the quote,
// reopen. Safe for every byte a filename can hold except NUL.
function shq(word) {
  return `'${String(word).replace(/'/g, `'\\''`)}'`;
}

// Like shq, but lets a leading ~ expand on the *remote* side: "$HOME" is left
// unquoted-but-double-quoted so the remote shell expands it, and the rest stays
// literal. Only ever used for the connect probe -- the probe reports back the
// absolute path it landed in, and every later command quotes that with shq.
function shqPath(p) {
  const s = String(p == null ? '' : p);
  if (s === '~') return '"$HOME"';
  if (s.startsWith('~/')) return '"$HOME"/' + shq(s.slice(2));
  return shq(s);
}

/* ----- remote path containment ----- */

// The remote twin of WorkspaceManager.resolveSafe. path.posix explicitly: the
// remote is POSIX even when Tote is running on Windows, and a backslash is a
// legal filename byte there rather than a separator. An absolute `rel` resolves
// away from the root and is caught by the same containment check.
function remoteResolve(root, rel) {
  const r = path.posix.resolve('/', String(root));
  const abs = path.posix.resolve(r, String(rel == null ? '' : rel));
  if (abs !== r && !abs.startsWith(r + '/')) throw new Error('Path escapes workspace root');
  return abs;
}

/* ----- ssh invocations -------------------------------------------------------
 *
 * One multiplexed master per space. New channels over an already-authenticated
 * master do not re-trigger Tailscale's periodic check -- only a new connection
 * does -- so the master's lifetime is what sets how often the user has to
 * re-authenticate. ControlPersist=yes keeps it until something actually breaks;
 * the keepalives are what make it notice a dead link instead of wedging.
 */

const PERSIST = ['-o', 'ControlPersist=yes', '-o', 'ServerAliveInterval=30',
                 '-o', 'ServerAliveCountMax=3'];

// -o takes a *config line*, which ssh splits on whitespace -- so a socket under
// "~/Library/Application Support/Tote" fails before it ever connects, with
// "keyword controlpath extra arguments at end of line". ssh_config allows a
// double-quoted value, and quoting is harmless when there is no space, so it is
// applied unconditionally rather than only when a space happens to be present.
const ctl = (socket) => `ControlPath="${socket}"`;

// The interactive master. This is the ONLY invocation allowed to authenticate,
// which is why it needs a tty: a host-key question, a key passphrase and
// Tailscale's "visit this URL" check all block here until the user acts.
function connectArgs({ host, socket, root, mkdir }) {
  return ['-tt', '-o', 'ControlMaster=auto', '-o', ctl(socket), ...PERSIST,
          '-o', 'StrictHostKeyChecking=accept-new', host, probeScript(root, mkdir)];
}

// The same master, established without a human. Most drops -- sleep, a wifi
// hop, a tailnet reconnect -- need no authentication at all, so this heals them
// invisibly; BatchMode means the ones that DO need a human fail immediately
// rather than blocking on a URL nobody is looking at, and get escalated to
// connectArgs above.
function silentConnectArgs({ host, socket, root }) {
  return ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ControlMaster=auto',
          '-o', ctl(socket), ...PERSIST,
          '-o', 'StrictHostKeyChecking=accept-new', host, probeScript(root, false)];
}

// Resolve ~ once, on the remote, and report the absolute result back. Every
// later command uses that, so shq() alone is enough from here on.
function probeScript(root, mkdir) {
  const p = shqPath(root);
  return [
    mkdir ? `mkdir -p ${p} 2>/dev/null;` : '',
    `cd ${p} || { printf 'TOTE_ERR=nodir\\n'; exit 3; }`,
    `printf 'TOTE_ROOT=%s\\n' "$(pwd)"`,
  ].filter(Boolean).join('\n');
}

// Every non-interactive op. BatchMode stops ssh's OWN prompts (passphrase, host
// key) -- but it is NOT enough on its own, and believing it was is how this hung
// in the first place. Tailscale serves its periodic check from the far side
// AFTER the connection is established, so BatchMode never sees it and
// ConnectTimeout (which bounds the handshake only) has long since elapsed: ssh
// sits holding an open session while a "visit this URL" banner waits on stderr.
// The wall-clock timeout and the needsHuman sniffer in remote.js are what
// actually bound this; see exec() there.
function runArgs({ host, socket, command }) {
  return ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'ControlMaster=no',
          '-o', ctl(socket), host, command];
}

// A terminal: needs a tty, rides the master, and deliberately does NOT set
// BatchMode. If the master has gone away, prompting is the right behaviour here
// -- a terminal is exactly the place a human can answer, so a dead master turns
// into a visible reconnect rather than a silent failure.
function termArgs({ host, socket, command }) {
  return ['-tt', '-o', 'ControlMaster=no', '-o', ctl(socket),
          '-o', 'StrictHostKeyChecking=accept-new', host, command];
}

// Is the master alive? Cheap enough to use as a heartbeat.
function checkArgs({ host, socket }) {
  return ['-O', 'check', '-o', ctl(socket), host];
}

function exitArgs({ host, socket }) {
  return ['-O', 'exit', '-o', ctl(socket), host];
}

/* ----- remote commands ----- */

// A terminal. The remote login shell for the same reason the local one is used
// (fnm/nvm/asdf put the agent behind a per-shell bin dir), and exec so the agent
// owns the pty directly: signals, exit code and TUI repaint behave as local.
function termCommand(root, profile) {
  const cd = 'cd ' + shq(root);
  const args = (profile && profile.args) || [];
  if (!profile || !profile.command) return cd + ' && exec "$SHELL" -l -i';
  const inner = 'exec ' + [profile.command, ...args].map(shq).join(' ');
  return cd + ' && exec "$SHELL" -l -i -c ' + shq(inner);
}

// Two finds rather than one: -printf would tell us the type in a single pass
// but it is GNU-only, and the remote may be macOS. The prune list makes both
// passes cheap, and the second one runs against a warm directory cache.
function treeCommand(root, depth, ignore) {
  const prune = (ignore || []).length
    ? '\\( ' + ignore.map((n) => '-name ' + shq(n)).join(' -o ') + ' \\) -prune -o '
    : '';
  const find = (type) =>
    `find . -maxdepth ${depth} ${prune}-type ${type} -print | sed -e 's|^|${type} |'`;
  return `cd ${shq(root)} || exit 3\n${find('d')}\n${find('f')}`;
}

// A cheap "has anything changed" probe, hashed on the remote so the answer is
// one line however big the project is. It has to cover content as well as
// structure: the whole point of a remote space is an agent editing files in a
// terminal, and a doc pane only learns about that from this fingerprint. Hence
// `ls -ld` per file (batched by xargs into a handful of processes) rather than
// find's output alone, which would miss an in-place edit.
function fingerprintCommand(root, depth, ignore) {
  const prune = (ignore || []).length
    ? '\\( ' + ignore.map((n) => '-name ' + shq(n)).join(' -o ') + ' \\) -prune -o '
    : '';
  return `cd ${shq(root)} || exit 3\n` +
    `{ find . -maxdepth ${depth} ${prune}-type d -print; ` +
    `find . -maxdepth ${depth} ${prune}-type f -print0 | xargs -0 ls -ld 2>/dev/null; } | cksum`;
}

// One round trip for "does it exist, is it a file, how big, how old". The two
// stat spellings are tried in order because -c is GNU and -f is BSD, and the
// remote may be either; mtime only has to be good enough to notice a change.
function statCommand(abs) {
  const p = shq(abs);
  return [
    `[ -e ${p} ] || { echo TOTE_STAT=none; exit 0; }`,
    `[ -d ${p} ] && { echo TOTE_STAT=dir; exit 0; }`,
    `echo TOTE_STAT=file`,
    // BSD wc left-pads its count, and command substitution word-splits it into
    // "TOTE_SIZE= 6" -- so the digits are stripped clean here as well as being
    // parsed leniently below.
    `echo TOTE_SIZE=$(wc -c < ${p} | tr -d '[:space:]')`,
    `echo TOTE_MTIME=$(stat -c %Y ${p} 2>/dev/null || stat -f %m ${p} 2>/dev/null || echo 0)`,
  ].join('\n');
}

const catCommand = (abs) => `cat -- ${shq(abs)}`;

// Content arrives on stdin, so it never passes through a shell at all.
const writeCommand = (abs) => `mkdir -p ${shq(posixDir(abs))} && cat > ${shq(abs)}`;

// The collision marker goes to stderr, not stdout: that is where a failed
// command's message is read from, and putting it anywhere else makes the guard
// depend on which stream happened to be non-empty.
function createFileCommand(abs) {
  const p = shq(abs);
  return `[ -e ${p} ] && { echo TOTE_ERR=exists >&2; exit 4; }\nmkdir -p ${shq(posixDir(abs))} && : > ${p}`;
}

function mkdirCommand(abs) {
  const p = shq(abs);
  return `[ -e ${p} ] && { echo TOTE_ERR=exists >&2; exit 4; }\nmkdir -p ${p}`;
}

const renameCommand = (from, to) =>
  `mkdir -p ${shq(posixDir(to))} && mv -- ${shq(from)} ${shq(to)}`;

// There is no remote wastebasket to hand this to, so a remote trash is a move
// into the space's own .tote-trash/. Deliberately never `rm`: the local side
// goes through shell.trashItem and is recoverable, and so is this.
function trashCommand(abs, trashDir, stamp) {
  const target = trashDir + '/' + posixBase(abs) + '.' + stamp;
  return `mkdir -p ${shq(trashDir)} && mv -- ${shq(abs)} ${shq(target)}`;
}

const mkdirpCommand = (abs) => `mkdir -p ${shq(abs)}`;

// A remote inbox filename that is free right now. Same "(1)", "(2)" shape the
// local ingest uses, decided from a listing rather than by probing one by one.
function freeName(base, taken) {
  const used = new Set(taken || []);
  if (!used.has(base)) return base;
  const cut = base.lastIndexOf('.');
  const stem = cut > 0 ? base.slice(0, cut) : base;
  const ext = cut > 0 ? base.slice(cut) : '';
  for (let i = 1; ; i++) {
    const candidate = `${stem} (${i})${ext}`;
    if (!used.has(candidate)) return candidate;
  }
}

const posixDir = (p) => path.posix.dirname(p);
const posixBase = (p) => path.posix.basename(p);

/* ----- output parsing ----- */

function parseStat(out) {
  const text = stripAnsi(out);
  const type = (text.match(/TOTE_STAT=(\w+)/) || [])[1] || 'none';
  if (type !== 'file') return { type };
  const num = (re) => Number((text.match(re) || [])[1] || 0);
  return { type, size: num(/TOTE_SIZE=\s*(\d+)/), mtimeMs: num(/TOTE_MTIME=\s*(\d+)/) * 1000 };
}

function parseProbe(out) {
  const text = stripAnsi(out);
  if (/TOTE_ERR=nodir/.test(text)) return { ok: false, error: 'no such directory on the remote' };
  const m = text.match(/TOTE_ROOT=(.+)/);
  if (!m) return { ok: false, error: null };       // null: nothing conclusive yet
  return { ok: true, root: m[1].trim() };
}

// "d ./src" / "f ./src/app.js" -> the same node shape tree() builds locally.
// decorate(name) supplies the per-file fields (text, kind) so this stays pure
// and the two trees can never disagree about a file's kind.
function buildTree(out, decorate) {
  const root = { children: [] };
  const dirs = new Map([['.', root]]);
  const parentOf = (rel) => {
    const cut = rel.lastIndexOf('/');
    const parentRel = cut === -1 ? '.' : rel.slice(0, cut);
    let node = dirs.get(parentRel);
    if (!node) {                                    // a find race, or a pruned parent
      node = { name: parentRel.split('/').pop(), path: parentRel, type: 'dir', children: [] };
      dirs.set(parentRel, node);
      parentOf(parentRel).children.push(node);
    }
    return node;
  };
  for (const line of stripAnsi(out).split(/\r?\n/)) {
    const m = line.match(/^([df]) \.\/(.+)$/);
    if (!m) continue;
    const [, type, rel] = m;
    const name = rel.split('/').pop();
    if (type === 'd') {
      if (dirs.has(rel)) continue;
      const node = { name, path: rel, type: 'dir', children: [] };
      dirs.set(rel, node);
      parentOf(rel).children.push(node);
    } else {
      parentOf(rel).children.push({ name, path: rel, type: 'file', ...decorate(name) });
    }
  }
  const sort = (nodes) => {
    nodes.sort((a, b) =>
      a.type !== b.type ? (a.type === 'dir' ? -1 : 1) : a.name.localeCompare(b.name));
    for (const n of nodes) if (n.children) sort(n.children);
    return nodes;
  };
  return sort(root.children);
}

/* ----- detectors -------------------------------------------------------------
 *
 * Read as: what does this output mean, and can the user do something about it.
 * Kept separate rather than folded into classify() so each can be tested against
 * the real output that produced it.
 */

// Tailscale's periodic re-check and a logged-out tailscaled both come down to
// "a URL appeared and the process is blocked until you visit it". The domain
// match covers Tailscale proper; the "To authenticate, visit:" form also covers
// a self-hosted control plane.
function authUrl(out) {
  const text = stripAnsi(out);
  const direct = text.match(/https:\/\/login\.tailscale\.com\/[^\s'"<>]+/);
  if (direct) return direct[0];
  const prompted = text.match(/To authenticate, visit:?\s+(https?:\/\/[^\s'"<>]+)/i);
  return prompted ? prompted[1] : null;
}

// First contact with an unknown host. Returns the fingerprint so the UI can
// show what it is being asked to trust.
function hostKeyPrompt(out) {
  const text = stripAnsi(out);
  if (!/Are you sure you want to continue connecting/i.test(text)) return null;
  const fp = text.match(/key fingerprint is (\S+)/i);
  return fp ? fp[1] : 'unknown';
}

// Never auto-accepted, by us or by StrictHostKeyChecking=accept-new. Separate
// from hostKeyPrompt because the right response is the opposite one.
function hostKeyChanged(out) {
  return /REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(stripAnsi(out));
}

// The master went away: laptop slept, tailnet reconnected, ControlPersist was
// killed. Recoverable by reconnecting, and usually without re-auth.
function socketDead(out) {
  const text = stripAnsi(out);
  return /Control socket connect\([^)]*\):/i.test(text)
    || /mux_client_request_session/i.test(text)
    || /Session open refused by peer/i.test(text)
    // Real drops read "Connection closed by 100.116.93.5 port 22", not the
    // "...by remote host" wording; matching only the latter missed every one.
    || /Connection closed by /i.test(text)
    || /Connection reset by peer/i.test(text)
    || /broken pipe/i.test(text);
}

function denied(out) {
  return /Permission denied \(/i.test(stripAnsi(out));
}

// The name does not resolve at all. Split out from `unreachable` because the
// two have opposite fixes: a peer that is merely asleep needs waking, a name
// that does not resolve is almost always a typo or a machine not on the
// tailnet, and "is it online?" sends the user to check the wrong thing.
function unknownHost(out) {
  const text = stripAnsi(out);
  return /Could not resolve hostname/i.test(text)
    || /Name or service not known/i.test(text)
    || /nodename nor servname provided/i.test(text);
}

// Reachable name, unreachable machine -- tailscaled down, peer asleep, no route.
function unreachable(out) {
  const text = stripAnsi(out);
  return /No route to host/i.test(text)
    || /Network is unreachable/i.test(text)
    || /Connection timed out/i.test(text)
    || /Operation timed out/i.test(text)
    || /Connection refused/i.test(text);
}

// Tailscale SSH maps the tailnet identity onto a LOCAL unix account on the
// remote, so connecting as your laptop's username to a box that has never heard
// of it fails here rather than at authentication. Captured against a real
// tailnet: the fix is user@host, which is why the username is reported back.
function noSuchUser(out) {
  const m = stripAnsi(out).match(/failed to look up local user "([^"]*)"/i);
  return m ? m[1] : null;
}

// `tailscale status` when the local daemon has no session.
function loggedOut(out) {
  const text = stripAnsi(out);
  return /^\s*Logged out\./im.test(text) || /NeedsLogin/.test(text);
}

// Does this output show something only a human at a terminal can resolve?
//
// This is the difference between an operation that will fail and one that will
// HANG. Tailscale's periodic check is served by the remote *after* the
// connection is established, so BatchMode never sees it and ConnectTimeout has
// long since elapsed: ssh simply sits there holding an open session while the
// banner waits to be read. A non-interactive op has no way to answer, so the
// only correct move is to stop waiting and hand the problem to RemoteConn.
// Captured in the wild: the URL arrives within the first packet, so scanning a
// couple of KB of head is enough.
function needsHuman(out) {
  const k = classify(out).kind;
  return k === 'auth' || k === 'hostKey' || k === 'hostKeyChanged';
}

// One answer for the connection actor, worst-actionable-first: an auth URL is
// worth surfacing even if the same buffer also shows the session dropping,
// because visiting it is what unblocks the reconnect.
function classify(out) {
  if (hostKeyChanged(out)) return { kind: 'hostKeyChanged' };
  const url = authUrl(out);
  if (url) return { kind: 'auth', url };
  const fp = hostKeyPrompt(out);
  if (fp) return { kind: 'hostKey', fingerprint: fp };
  // Before denied/socketDead: this failure closes the connection, so both of
  // those also match, and neither of them tells the user what to change.
  const user = noSuchUser(out);
  if (user !== null) return { kind: 'noSuchUser', user };
  if (denied(out)) return { kind: 'denied' };
  // Before unreachable: a name that does not resolve is its own problem, with
  // its own fix, and the generic wording would hide it.
  if (unknownHost(out)) {
    const m = stripAnsi(out).match(/Could not resolve hostname (\S+?):/i);
    return { kind: 'unknownHost', host: m ? m[1] : null };
  }
  if (unreachable(out)) return { kind: 'unreachable' };
  if (socketDead(out)) return { kind: 'socketDead' };
  return { kind: 'unknown' };
}

// The message for a classify() result, which can carry detail a bare state
// cannot -- the username that does not exist, the fingerprint being offered.
function describe(cls) {
  if (!cls) return explain('down');
  if (cls.kind === 'noSuchUser') {
    return `No user "${cls.user}" on that host - set the space's host to user@host`;
  }
  if (cls.kind === 'unknownHost') {
    return cls.host
      ? `No host named "${cls.host}" - check the spelling, or that it is on your tailnet`
      : explain('unknownHost');
  }
  if (cls.kind === 'hostKey') return 'Unknown host, fingerprint ' + cls.fingerprint;
  return explain(cls.kind);
}

// What to tell the user, in the files pane banner and on the space chip.
function explain(state) {
  switch (state) {
    case 'noSuchUser': return 'No such user on that host - use user@host';
    case 'unknownHost': return 'That host name does not resolve - check the spelling';
    case 'auth': return 'Re-authenticate to continue';
    case 'hostKeyChanged': return 'Host key changed - verify the host before reconnecting';
    case 'hostKey': return 'Unknown host - confirm the fingerprint in the connect pane';
    case 'denied': return 'Permission denied by the remote host';
    case 'unreachable': return 'Host unreachable - is it online and on the tailnet?';
    case 'socketDead': return 'Connection dropped - reconnect';
    case 'connecting': return 'Connecting...';
    case 'up': return 'Connected';
    default: return 'Disconnected';
  }
}

module.exports = {
  stripAnsi, shq, shqPath, remoteResolve,
  connectArgs, silentConnectArgs, probeScript, runArgs, termArgs, checkArgs, exitArgs,
  termCommand, treeCommand, fingerprintCommand, parseProbe, buildTree, parseStat,
  statCommand, catCommand, writeCommand, createFileCommand, mkdirCommand,
  renameCommand, trashCommand, mkdirpCommand, freeName, posixDir, posixBase,
  authUrl, hostKeyPrompt, hostKeyChanged, socketDead, denied, unreachable, loggedOut,
  classify, explain, describe, noSuchUser, unknownHost, needsHuman,
};
