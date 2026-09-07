#!/usr/bin/env node
// Dependency-free tests for remote spaces' pure half: shell quoting, the
// commands we send over ssh, remote path containment, the tree parser and the
// ssh/Tailscale output detectors. Run: node scripts/test-remote.js
//
// These cover the two things that are otherwise only testable by breaking a
// live connection: exactly what reaches a remote shell, and what we conclude
// from what comes back.
const assert = require('assert');
const S = require('../src/main/sshfix.js');

let pass = 0, fail = 0;
const describe = (name, fn) => { console.log('\n' + name); fn(); };
const test = (name, fn) => {
  try { fn(); pass++; console.log('  \x1b[32m✓\x1b[0m ' + name); }
  catch (e) { fail++; console.log('  \x1b[31m✗\x1b[0m ' + name + '\n      ' + e.message); }
};

describe('shq', () => {
  test('quotes a plain word', () => {
    assert.strictEqual(S.shq('proj'), "'proj'");
  });
  test('survives spaces', () => {
    assert.strictEqual(S.shq('my proj'), "'my proj'");
  });
  test('closes and reopens around a single quote', () => {
    assert.strictEqual(S.shq("it's"), "'it'\\''s'");
  });
  test('neutralises command substitution', () => {
    assert.strictEqual(S.shq('$(rm -rf /)'), "'$(rm -rf /)'");
  });
  test('neutralises a trailing semicolon', () => {
    assert.strictEqual(S.shq('a; rm -rf ~'), "'a; rm -rf ~'");
  });
  test('a backslash stays literal', () => {
    assert.strictEqual(S.shq('a\\b'), "'a\\b'");
  });
});

describe('shqPath', () => {
  test('a bare tilde becomes $HOME', () => {
    assert.strictEqual(S.shqPath('~'), '"$HOME"');
  });
  test('~/x expands the home half and quotes the rest', () => {
    assert.strictEqual(S.shqPath('~/proj/app'), `"$HOME"/'proj/app'`);
  });
  test('an absolute path is quoted whole', () => {
    assert.strictEqual(S.shqPath('/home/yk/proj'), "'/home/yk/proj'");
  });
  test('a tilde that is not a home prefix stays literal', () => {
    assert.strictEqual(S.shqPath('~weird'), "'~weird'");
  });
  test('injection through the tilde branch is still quoted', () => {
    assert.strictEqual(S.shqPath('~/a; rm -rf /'), `"$HOME"/'a; rm -rf /'`);
  });
});

describe('remoteResolve', () => {
  const root = '/home/yk/proj';
  test('resolves a relative path under the root', () => {
    assert.strictEqual(S.remoteResolve(root, 'src/app.js'), '/home/yk/proj/src/app.js');
  });
  test('the root itself resolves to the root', () => {
    assert.strictEqual(S.remoteResolve(root, '.'), root);
  });
  test('rejects a climb out of the root', () => {
    assert.throws(() => S.remoteResolve(root, '../secrets'), /escapes/);
  });
  test('rejects a climb that lands back inside a sibling prefix', () => {
    assert.throws(() => S.remoteResolve(root, '../proj-evil/x'), /escapes/);
  });
  test('rejects an absolute path', () => {
    assert.throws(() => S.remoteResolve(root, '/etc/passwd'), /escapes/);
  });
  test('a climb that returns inside is allowed', () => {
    assert.strictEqual(S.remoteResolve(root, 'src/../lib/x'), '/home/yk/proj/lib/x');
  });
  test('a backslash is a filename byte, not a separator', () => {
    assert.strictEqual(S.remoteResolve(root, 'a\\b'), '/home/yk/proj/a\\b');
  });
  test('uses posix separators regardless of the local platform', () => {
    assert.ok(!S.remoteResolve(root, 'src/app.js').includes('\\'));
  });
});

describe('connectArgs', () => {
  const args = S.connectArgs({ host: 'devbox', socket: '/tmp/s.sock', root: '~/proj' });
  test('forces a tty so auth prompts can be answered', () => {
    assert.ok(args.includes('-tt'));
  });
  test('persists the master indefinitely, not for a few minutes', () => {
    assert.ok(args.includes('ControlPersist=yes'));
  });
  test('carries keepalives so a dead link is noticed', () => {
    assert.ok(args.includes('ServerAliveInterval=30'));
  });
  test('accepts a new host key but never a changed one', () => {
    assert.ok(args.includes('StrictHostKeyChecking=accept-new'));
  });
  test('never sets BatchMode - this is the one call that may prompt', () => {
    assert.ok(!args.some((a) => /BatchMode/.test(a)));
  });
  test('the host comes before the remote script', () => {
    assert.strictEqual(args[args.length - 2], 'devbox');
  });
  test('the whole remote script is a single argv element', () => {
    assert.ok(args[args.length - 1].includes('\n'));
  });
});

describe('silentConnectArgs', () => {
  const args = S.silentConnectArgs({ host: 'devbox', socket: '/tmp/s.sock', root: '/home/yk/p' });
  test('never prompts - a drop that needs a human is escalated, not blocked on', () => {
    assert.ok(args.includes('BatchMode=yes'));
    assert.ok(!args.includes('-tt'));
  });
  test('may open a master, unlike an ordinary op', () => {
    assert.ok(args.includes('ControlMaster=auto'));
  });
  test('persists the same way, so the healed master lasts', () => {
    assert.ok(args.includes('ControlPersist=yes'));
  });
  test('runs the same probe, so root is re-confirmed after a reconnect', () => {
    assert.ok(args[args.length - 1].includes('TOTE_ROOT'));
  });
  test('never creates the directory - that is a create-space decision only', () => {
    assert.ok(!args[args.length - 1].includes('mkdir'));
  });
});

describe('probeScript', () => {
  test('reports the absolute path it landed in', () => {
    assert.ok(S.probeScript('~/proj', false).includes("printf 'TOTE_ROOT=%s\\n'"));
  });
  test('fails loudly when the directory is missing', () => {
    assert.ok(S.probeScript('/nope', false).includes('TOTE_ERR=nodir'));
  });
  test('does not create the directory by default', () => {
    assert.ok(!S.probeScript('/x', false).includes('mkdir'));
  });
  test('creates it when the caller asked (new remote space)', () => {
    assert.ok(S.probeScript('~/new', true).includes(`mkdir -p "$HOME"/'new'`));
  });
});

describe('runArgs', () => {
  const args = S.runArgs({ host: 'devbox', socket: '/tmp/s.sock', command: 'ls' });
  test('BatchMode so a challenged op fails instead of hanging', () => {
    assert.ok(args.includes('BatchMode=yes'));
  });
  test('a short connect timeout so the files pane never spins', () => {
    assert.ok(args.includes('ConnectTimeout=5'));
  });
  test('never opens its own master - ops do not authenticate', () => {
    assert.ok(args.includes('ControlMaster=no'));
  });
  test('rides the space socket', () => {
    assert.ok(args.includes('ControlPath="/tmp/s.sock"'));
  });
});

describe('checkArgs / exitArgs', () => {
  test('check asks the master whether it is alive', () => {
    assert.deepStrictEqual(S.checkArgs({ host: 'h', socket: '/s' }).slice(0, 2), ['-O', 'check']);
  });
  test('exit tears the master down', () => {
    assert.deepStrictEqual(S.exitArgs({ host: 'h', socket: '/s' }).slice(0, 2), ['-O', 'exit']);
  });
  // A staged download is pushed with ssh + `cat >`, not scp: scp's remote path
  // is shell-expanded by the pre-9.0 backend and passed literally by the SFTP
  // one, so a filename with a space breaks whichever way it is quoted. Going
  // through ssh puts it back under shq(), like every other remote path.
  test('there is no scp builder to get that wrong with', () => {
    assert.strictEqual(S.scpArgs, undefined);
  });
  test('an upload target with a space is shell-quoted by writeCommand', () => {
    const c = S.writeCommand('/r/inbox/kimi/My Report (1).pdf');
    assert.ok(c.includes(`'/r/inbox/kimi/My Report (1).pdf'`), c);
    assert.ok(c.includes(`mkdir -p '/r/inbox/kimi'`), c);
  });
});

describe('ControlPath quoting', () => {
  // Regression: the default socket lives under "~/Library/Application Support/
  // Tote/ssh" on macOS. -o takes a config LINE, which ssh splits on whitespace,
  // so an unquoted value failed every single remote operation before it even
  // connected: "keyword controlpath extra arguments at end of line".
  const SPACED = '/Users/yk/Library/Application Support/Tote/ssh/a.sock';
  const builders = {
    connectArgs: S.connectArgs({ host: 'h', socket: SPACED, root: '~/p' }),
    silentConnectArgs: S.silentConnectArgs({ host: 'h', socket: SPACED, root: '/p' }),
    runArgs: S.runArgs({ host: 'h', socket: SPACED, command: 'ls' }),
    termArgs: S.termArgs({ host: 'h', socket: SPACED, command: 'ls' }),
    checkArgs: S.checkArgs({ host: 'h', socket: SPACED }),
    exitArgs: S.exitArgs({ host: 'h', socket: SPACED }),
  };
  for (const [name, args] of Object.entries(builders)) {
    test(name + ' quotes a socket path containing a space', () => {
      assert.ok(args.includes(`ControlPath="${SPACED}"`), args.join(' '));
    });
  }
  test('every builder that takes a socket is covered above', () => {
    const takesSocket = Object.keys(S).filter((k) => /Args$/.test(k));
    assert.deepStrictEqual(takesSocket.sort(), Object.keys(builders).sort());
  });
  test('quoting is unconditional, so there is no space-only code path', () => {
    assert.ok(S.checkArgs({ host: 'h', socket: '/tmp/plain.sock' }).includes('ControlPath="/tmp/plain.sock"'));
  });
});

describe('termCommand', () => {
  test('cds into the space root before exec', () => {
    const c = S.termCommand('/home/yk/proj', { command: 'claude', args: [] });
    assert.ok(c.startsWith("cd '/home/yk/proj' &&"));
  });
  test('goes through the remote login shell for the agent PATH', () => {
    const c = S.termCommand('/r', { command: 'claude', args: [] });
    assert.ok(c.includes('"$SHELL" -l -i -c'));
  });
  test('execs so the agent owns the pty directly', () => {
    assert.ok(S.termCommand('/r', { command: 'claude', args: [] }).includes("'exec '\\''claude'\\'''"));
  });
  test('an empty command means the plain remote login shell', () => {
    assert.strictEqual(S.termCommand('/r', { command: '' }), `cd '/r' && exec "$SHELL" -l -i`);
  });
  test('a missing profile is treated as the plain shell', () => {
    assert.ok(S.termCommand('/r', null).endsWith('exec "$SHELL" -l -i'));
  });
  test('args are quoted individually', () => {
    const c = S.termCommand('/r', { command: 'claude', args: ['--model', 'opus 5'] });
    assert.ok(c.includes(`'opus 5'`));
  });
  test('a hostile root cannot break out of the cd', () => {
    const c = S.termCommand("/r'; rm -rf ~; '", { command: '' });
    assert.ok(c.startsWith(`cd '/r'\\''; rm -rf ~; '\\'''`));
  });
});

describe('treeCommand', () => {
  const cmd = S.treeCommand('/home/yk/proj', 5, ['node_modules', '.git', '.godot']);
  test('bails when the root is gone rather than listing the home dir', () => {
    assert.ok(cmd.startsWith("cd '/home/yk/proj' || exit 3"));
  });
  test('prunes every ignored directory', () => {
    assert.ok(cmd.includes("-name 'node_modules' -o -name '.git' -o -name '.godot'"));
  });
  test('escapes the find parens for the remote shell', () => {
    assert.ok(cmd.includes('\\( ') && cmd.includes(' \\) -prune -o '));
  });
  test('maxdepth comes first, as both GNU and BSD find want', () => {
    assert.ok(/find \. -maxdepth 5 /.test(cmd));
  });
  test('tags dirs and files in two passes, since -printf is GNU-only', () => {
    assert.ok(cmd.includes("-type d -print | sed -e 's|^|d |'"));
    assert.ok(cmd.includes("-type f -print | sed -e 's|^|f |'"));
  });
  test('an empty ignore list produces no prune clause', () => {
    assert.ok(!S.treeCommand('/r', 3, []).includes('-prune'));
  });
});

describe('parseProbe', () => {
  test('reads the absolute root back out', () => {
    const r = S.parseProbe('TOTE_ROOT=/home/yk/proj\r\n');
    assert.deepStrictEqual(r, { ok: true, root: '/home/yk/proj' });
  });
  test('sees through the tty echo and colour', () => {
    const r = S.parseProbe('\x1b[0m$ probe\r\nTOTE_ROOT=/srv/app\r\n');
    assert.strictEqual(r.root, '/srv/app');
  });
  test('a missing directory is a definite failure', () => {
    assert.strictEqual(S.parseProbe('TOTE_ERR=nodir\r\n').ok, false);
    assert.ok(/directory/.test(S.parseProbe('TOTE_ERR=nodir').error));
  });
  test('nothing conclusive yet is not an error', () => {
    assert.deepStrictEqual(S.parseProbe('Last login: Sun\r\n'), { ok: false, error: null });
  });
});

describe('buildTree', () => {
  const kind = (name) => ({ text: /\.(js|md)$/.test(name), kind: /\.md$/.test(name) ? 'md' : 'text' });
  const OUT = [
    'd ./src', 'd ./src/main', 'd ./docs',
    'f ./README.md', 'f ./src/main/app.js', 'f ./docs/notes.md',
  ].join('\n');

  test('nests files under the directories find printed first', () => {
    const t = S.buildTree(OUT, kind);
    assert.deepStrictEqual(t.map((n) => n.name), ['docs', 'src', 'README.md']);
    assert.strictEqual(t.find((n) => n.name === 'src').children[0].name, 'main');
  });
  test('directories sort before files, then alphabetically', () => {
    const t = S.buildTree('f ./b.txt\nd ./a\nf ./a.txt', kind);
    assert.deepStrictEqual(t.map((n) => n.name), ['a', 'a.txt', 'b.txt']);
  });
  test('paths are workspace-relative, with no ./ prefix', () => {
    const t = S.buildTree(OUT, kind);
    assert.strictEqual(t.find((n) => n.name === 'src').children[0].children[0].path, 'src/main/app.js');
  });
  test('decorate supplies text and kind, so both trees agree', () => {
    const t = S.buildTree('f ./README.md', kind);
    assert.deepStrictEqual(t[0], { name: 'README.md', path: 'README.md', type: 'file', text: true, kind: 'md' });
  });
  test('the root dot is not a node', () => {
    assert.strictEqual(S.buildTree('d ./\nd ./src', kind).length, 1);
  });
  test('a file whose parent was never printed still lands somewhere', () => {
    const t = S.buildTree('f ./ghost/x.js', kind);
    assert.strictEqual(t[0].name, 'ghost');
    assert.strictEqual(t[0].children[0].path, 'ghost/x.js');
  });
  test('a duplicated directory line is not duplicated in the tree', () => {
    assert.strictEqual(S.buildTree('d ./src\nd ./src', kind).length, 1);
  });
  test('empty output is an empty tree, not a crash', () => {
    assert.deepStrictEqual(S.buildTree('', kind), []);
  });
  test('a name with a space survives', () => {
    assert.strictEqual(S.buildTree('f ./my notes.md', kind)[0].name, 'my notes.md');
  });
});

describe('file-op commands', () => {
  test('stat answers existence, type, size and mtime in one round trip', () => {
    const c = S.statCommand('/r/a.txt');
    assert.ok(c.includes('TOTE_STAT=none') && c.includes('TOTE_STAT=dir'));
    assert.ok(c.includes('TOTE_SIZE=') && c.includes('TOTE_MTIME='));
  });
  test('stat tries the GNU spelling then the BSD one', () => {
    const c = S.statCommand('/r/a');
    assert.ok(c.indexOf('stat -c %Y') < c.indexOf('stat -f %m'));
  });
  test('cat guards against a path that looks like a flag', () => {
    assert.strictEqual(S.catCommand('/r/-rf'), "cat -- '/r/-rf'");
  });
  test('write creates the parent and takes content on stdin, not in the command', () => {
    assert.strictEqual(S.writeCommand('/r/a/b.txt'), `mkdir -p '/r/a' && cat > '/r/a/b.txt'`);
  });
  test('createFile refuses to clobber, like the local one', () => {
    assert.ok(S.createFileCommand('/r/a.txt').includes('TOTE_ERR=exists'));
  });
  test('createFolder refuses to clobber too', () => {
    assert.ok(S.mkdirCommand('/r/a').includes('TOTE_ERR=exists'));
  });
  test('the collision marker goes to stderr, where a failure is read from', () => {
    assert.ok(S.createFileCommand('/r/a').includes('TOTE_ERR=exists >&2'));
    assert.ok(S.mkdirCommand('/r/a').includes('TOTE_ERR=exists >&2'));
  });
  test('rename creates the destination parent first', () => {
    assert.strictEqual(S.renameCommand('/r/a', '/r/x/b'), `mkdir -p '/r/x' && mv -- '/r/a' '/r/x/b'`);
  });
  test('trash moves into .tote-trash and never removes', () => {
    const c = S.trashCommand('/r/a.txt', '/r/.tote-trash', '1757200000');
    assert.ok(c.includes('mv --') && !/\brm\b/.test(c));
    assert.ok(c.includes(`'/r/.tote-trash/a.txt.1757200000'`));
  });
  test('every builder quotes a hostile filename', () => {
    const evil = "/r/a'; rm -rf ~; '.txt";
    for (const c of [S.catCommand(evil), S.writeCommand(evil), S.createFileCommand(evil),
                     S.mkdirCommand(evil), S.renameCommand(evil, evil), S.statCommand(evil),
                     S.trashCommand(evil, '/r/.t', '1')]) {
      assert.ok(!/;\s*rm -rf ~;\s*$/m.test(c.replace(/'\\''/g, '')), c);
      assert.ok(c.includes(`'\\''`), c);
    }
  });
});

describe('parseStat', () => {
  test('reads a file back', () => {
    const r = S.parseStat('TOTE_STAT=file\nTOTE_SIZE=1234\nTOTE_MTIME=1757200000\n');
    assert.deepStrictEqual(r, { type: 'file', size: 1234, mtimeMs: 1757200000000 });
  });
  test('a directory carries no size', () => {
    assert.deepStrictEqual(S.parseStat('TOTE_STAT=dir\n'), { type: 'dir' });
  });
  test('a missing path is none, not a crash', () => {
    assert.deepStrictEqual(S.parseStat('TOTE_STAT=none\n'), { type: 'none' });
  });
  test('unparseable output is none rather than a zero-byte file', () => {
    assert.strictEqual(S.parseStat('bash: stat: command not found').type, 'none');
  });
  test('survives BSD wc padding the byte count', () => {
    // Real macOS output: `echo TOTE_SIZE=$(wc -c < f)` word-splits into a space.
    assert.strictEqual(S.parseStat('TOTE_STAT=file\nTOTE_SIZE= 6\nTOTE_MTIME= 1757200000\n').size, 6);
  });
  test('the command strips the padding at the source too', () => {
    assert.ok(S.statCommand('/r/a').includes("tr -d '[:space:]'"));
  });
  test('a stat that failed both spellings gives mtime 0, not NaN', () => {
    const r = S.parseStat('TOTE_STAT=file\nTOTE_SIZE=10\nTOTE_MTIME=0\n');
    assert.strictEqual(r.mtimeMs, 0);
  });
});

describe('freeName', () => {
  test('keeps the name when nothing collides', () => {
    assert.strictEqual(S.freeName('a.pdf', []), 'a.pdf');
  });
  test('suffixes before the extension, like the local ingest', () => {
    assert.strictEqual(S.freeName('a.pdf', ['a.pdf']), 'a (1).pdf');
  });
  test('walks past a run of collisions', () => {
    assert.strictEqual(S.freeName('a.pdf', ['a.pdf', 'a (1).pdf', 'a (2).pdf']), 'a (3).pdf');
  });
  test('an extensionless name suffixes at the end', () => {
    assert.strictEqual(S.freeName('README', ['README']), 'README (1)');
  });
  test('a dotfile is all suffix and is not split', () => {
    assert.strictEqual(S.freeName('.env', ['.env']), '.env (1)');
  });
});

/* Real output, captured against a Tailscale tailnet. */

const CHECK_MODE = [
  '# Tailscale SSH requires an additional check.',
  '# To authenticate, visit: https://login.tailscale.com/a/8f21c0d4e5b6',
  '',
].join('\r\n');

const TS_LOGGED_OUT = [
  'Logged out.',
  'To authenticate, visit:',
  '',
  '\thttps://login.tailscale.com/a/2b7e9911aa03',
  '',
].join('\r\n');

const HOST_KEY_NEW = [
  "The authenticity of host 'devbox (100.84.12.9)' can't be established.",
  'ED25519 key fingerprint is SHA256:6mZ0rL2xQ8vN1kPqW4hT7yJ3sB5cD9eF0gH2iK4lM6o.',
  'Are you sure you want to continue connecting (yes/no/[fingerprint])? ',
].join('\r\n');

const HOST_KEY_CHANGED = [
  '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
  '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @',
  '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
  'IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!',
].join('\r\n');

// Real output, captured 2026-09-07 connecting to a Linux tailnet peer as the
// macOS username: Tailscale SSH maps the tailnet identity onto a local account,
// and that account did not exist.
const NO_USER = [
  'tailscale: failed to look up local user "yusufkaraaslan" ',
  'Connection closed by 100.116.93.5 port 22',
].join('\r\n');

const SOCKET_GONE = 'Control socket connect(/Users/yk/Library/Application Support/Tote/ssh/dev.sock): No such file or directory\r\n';
const DENIED = 'yk@devbox: Permission denied (tailscale, publickey).\r\n';
const NO_HOST = 'ssh: Could not resolve hostname devbox: nodename nor servname provided, or not known\r\n';
const CLEAN = 'TOTE_ROOT=/home/yk/proj\r\n';

describe('authUrl', () => {
  test('finds the URL in Tailscale SSH check mode', () => {
    assert.strictEqual(S.authUrl(CHECK_MODE), 'https://login.tailscale.com/a/8f21c0d4e5b6');
  });
  test('finds the URL when the local daemon is logged out', () => {
    assert.strictEqual(S.authUrl(TS_LOGGED_OUT), 'https://login.tailscale.com/a/2b7e9911aa03');
  });
  test('handles a self-hosted control plane through the prompt wording', () => {
    const out = 'To authenticate, visit: https://hs.example.net/register/abc123\r\n';
    assert.strictEqual(S.authUrl(out), 'https://hs.example.net/register/abc123');
  });
  test('does not trail a closing quote into the URL', () => {
    assert.strictEqual(S.authUrl('visit "https://login.tailscale.com/a/xy" now'),
      'https://login.tailscale.com/a/xy');
  });
  test('clean output carries no URL', () => {
    assert.strictEqual(S.authUrl(CLEAN), null);
  });
});

describe('hostKeyPrompt', () => {
  test('returns the fingerprint being offered', () => {
    assert.strictEqual(S.hostKeyPrompt(HOST_KEY_NEW),
      'SHA256:6mZ0rL2xQ8vN1kPqW4hT7yJ3sB5cD9eF0gH2iK4lM6o.');
  });
  test('is not triggered by a clean connect', () => {
    assert.strictEqual(S.hostKeyPrompt(CLEAN), null);
  });
  test('a changed key is not a first-contact prompt', () => {
    assert.strictEqual(S.hostKeyPrompt(HOST_KEY_CHANGED), null);
  });
});

describe('hostKeyChanged', () => {
  test('catches the warning banner', () => {
    assert.strictEqual(S.hostKeyChanged(HOST_KEY_CHANGED), true);
  });
  test('a first-contact prompt is not a change', () => {
    assert.strictEqual(S.hostKeyChanged(HOST_KEY_NEW), false);
  });
});

describe('socketDead', () => {
  test('catches a missing control socket', () => {
    assert.strictEqual(S.socketDead(SOCKET_GONE), true);
  });
  test('catches a session refused by a stale master', () => {
    assert.strictEqual(S.socketDead('mux_client_request_session: session request failed'), true);
  });
  test('catches the link dropping mid-session', () => {
    assert.strictEqual(S.socketDead('Connection closed by remote host'), true);
  });
  test('catches the wording ssh actually uses, with an address and port', () => {
    assert.strictEqual(S.socketDead('Connection closed by 100.116.93.5 port 22'), true);
  });
  test('clean output is not a dead socket', () => {
    assert.strictEqual(S.socketDead(CLEAN), false);
  });
});

describe('unknownHost', () => {
  // Captured from the app: a hostname typed with a stray hyphen.
  const TYPO = 'ssh: Could not resolve hostname yusyus-server: nodename nor servname provided, or not known';
  test('a name that does not resolve is its own kind, not "unreachable"', () => {
    assert.strictEqual(S.classify(TYPO).kind, 'unknownHost');
    assert.strictEqual(S.unreachable(TYPO), false);
  });
  test('it names the host, because the fix is almost always the spelling', () => {
    const m = S.describe(S.classify(TYPO));
    assert.ok(m.includes('yusyus-server'), m);
    assert.ok(/spelling|tailnet/i.test(m), m);
  });
  test('the Linux wording is recognised too', () => {
    assert.strictEqual(S.unknownHost('ssh: Could not resolve hostname x: Name or service not known'), true);
  });
  test('a sleeping peer is unreachable, not an unknown host', () => {
    const asleep = 'ssh: connect to host devbox port 22: No route to host';
    assert.strictEqual(S.classify(asleep).kind, 'unreachable');
    assert.strictEqual(S.unknownHost(asleep), false);
  });
  test('a resolvable host that times out stays unreachable', () => {
    assert.strictEqual(S.classify('ssh: connect to host d port 22: Operation timed out').kind, 'unreachable');
  });
});

describe('denied / unreachable / loggedOut', () => {
  test('permission denied is recognised', () => {
    assert.strictEqual(S.denied(DENIED), true);
  });
  test('a resolve failure is an unknown host, not a refusal', () => {
    assert.strictEqual(S.unknownHost(NO_HOST), true);
    assert.strictEqual(S.denied(NO_HOST), false);
  });
  test('a sleeping peer times out', () => {
    assert.strictEqual(S.unreachable('ssh: connect to host devbox port 22: Operation timed out'), true);
  });
  test('tailscale status reports a logged-out daemon', () => {
    assert.strictEqual(S.loggedOut(TS_LOGGED_OUT), true);
  });
  test('a connected tailnet is not logged out', () => {
    assert.strictEqual(S.loggedOut('100.84.12.9   devbox   yk@   linux   -'), false);
  });
});

describe('noSuchUser', () => {
  test('reports the username the remote does not have', () => {
    assert.strictEqual(S.noSuchUser(NO_USER), 'yusufkaraaslan');
  });
  test('is not triggered by an ordinary refusal', () => {
    assert.strictEqual(S.noSuchUser(DENIED), null);
  });
});

describe('classify', () => {
  test('a missing local account outranks the dropped connection it causes', () => {
    // This failure also closes the connection, so socketDead matches too -- and
    // "connection dropped" would send the user chasing the wrong thing.
    assert.strictEqual(S.classify(NO_USER).kind, 'noSuchUser');
    assert.strictEqual(S.socketDead(NO_USER), true);
  });
  test('a changed host key outranks everything - it is never auto-handled', () => {
    assert.strictEqual(S.classify(HOST_KEY_CHANGED + SOCKET_GONE).kind, 'hostKeyChanged');
  });
  test('an auth URL outranks a dropped session, because visiting it unblocks', () => {
    const r = S.classify(SOCKET_GONE + CHECK_MODE);
    assert.strictEqual(r.kind, 'auth');
    assert.strictEqual(r.url, 'https://login.tailscale.com/a/8f21c0d4e5b6');
  });
  test('an unknown host asks for the fingerprint', () => {
    assert.strictEqual(S.classify(HOST_KEY_NEW).kind, 'hostKey');
  });
  test('permission denied is its own answer', () => {
    assert.strictEqual(S.classify(DENIED).kind, 'denied');
  });
  test('an unknown host, an unreachable one and a dead socket stay distinct', () => {
    assert.strictEqual(S.classify(NO_HOST).kind, 'unknownHost');
    assert.strictEqual(S.classify('ssh: connect to host d port 22: No route to host').kind, 'unreachable');
    assert.strictEqual(S.classify(SOCKET_GONE).kind, 'socketDead');
  });
  test('clean output classifies as unknown, never as a failure', () => {
    assert.strictEqual(S.classify(CLEAN).kind, 'unknown');
  });
});

describe('needsHuman', () => {
  // The distinction this draws is between an op that FAILS and one that HANGS.
  // Tailscale serves its check after the connection is up, so BatchMode never
  // sees it and ConnectTimeout has already elapsed: ssh holds the session open
  // forever. Verified against a live tailnet before this existed.
  test('the Tailscale check needs a human, so an op must stop waiting', () => {
    assert.strictEqual(S.needsHuman(CHECK_MODE), true);
  });
  test('an unknown host key needs a human too - nobody can answer in BatchMode', () => {
    assert.strictEqual(S.needsHuman(HOST_KEY_NEW), true);
  });
  test('a changed host key needs a human', () => {
    assert.strictEqual(S.needsHuman(HOST_KEY_CHANGED), true);
  });
  test('a plain refusal does NOT - it already failed, there is nothing to wait for', () => {
    assert.strictEqual(S.needsHuman(DENIED), false);
    assert.strictEqual(S.needsHuman(NO_USER), false);
    assert.strictEqual(S.needsHuman(NO_HOST), false);
  });
  test('a dropped socket does not need a human - it reconnects silently', () => {
    assert.strictEqual(S.needsHuman(SOCKET_GONE), false);
  });
  test('ordinary output never aborts an op', () => {
    assert.strictEqual(S.needsHuman('d ./src\nf ./README.md\n'), false);
    assert.strictEqual(S.needsHuman(CLEAN), false);
  });
});

describe('describe', () => {
  test('names the missing user and the fix', () => {
    const m = S.describe(S.classify(NO_USER));
    assert.ok(m.includes('yusufkaraaslan') && /user@host/.test(m));
  });
  test('carries the fingerprint for an unknown host', () => {
    const m = S.describe(S.classify(HOST_KEY_NEW));
    assert.ok(m.includes('SHA256:'));
  });
  test('falls back to the plain state wording', () => {
    assert.strictEqual(S.describe({ kind: 'unreachable' }), S.explain('unreachable'));
  });
  test('a missing classification is never a blank message', () => {
    assert.ok(S.describe(null).length > 3);
  });
});

describe('explain', () => {
  test('every connection state has user-facing wording', () => {
    for (const s of ['auth', 'hostKey', 'hostKeyChanged', 'denied', 'unreachable',
                     'socketDead', 'noSuchUser', 'unknownHost', 'connecting', 'up', 'down']) {
      assert.ok(S.explain(s).length > 3, s);
    }
  });
  test('re-auth is phrased as an action, not an error', () => {
    assert.ok(/authenticate/i.test(S.explain('auth')));
  });
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
