import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { linkSync, mkdtempSync, readFileSync, unlinkSync, rmdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { acceptedResult, adversarialCases, checkedExecutable, inspectFixture, observationMarker, parseArguments, passMarker } from '../tools/test-legacy-migration.mjs';

const { files, source, entrypoint } = inspectFixture();
const groups = Object.entries(files).filter(([path]) => /^groups[/][0-9]+[.]json$/.test(path));
const profiles = Object.entries(files).filter(([path]) => path.startsWith('profiles/'));

test('source corpus has exactly the historical-shaped allowlist', () => {
  assert.equal(Object.keys(files).length, 13);
  assert.equal(groups.length, 4);
  assert.equal(profiles.length, 5);
  for (const path of Object.keys(files)) {
    assert.match(path, /^(groups[/](?:[0-9]+|pm|nekobox)[.]json|profiles[/][0-9]+[.]json|routes_box[/]Synthetic(?:Active|Inactive))$/);
    assert.equal(typeof files[path], 'object');
  }
});

test('sparse IDs, non-ID tab/order and complete membership are intentional', () => {
  assert.deepEqual(files['groups/pm.json'].groups, [12, 7, 34, 21]);
  assert.deepEqual(files['groups/7.json'].order, [90, 41]);
  const seen = [];
  for (const [path, group] of groups) {
    assert.equal(path, `groups/${group.id}.json`);
    for (const id of group.order) {
      assert.equal(files[`profiles/${id}.json`].gid, group.id);
      seen.push(id);
    }
  }
  assert.equal(new Set(seen).size, 5);
  assert.deepEqual([...seen].sort((a, b) => a - b), [41, 90, 103, 205, 402]);
});

test('duplicate names cannot substitute IDs; optional kind really is omitted', () => {
  assert.equal(files['profiles/41.json'].bean.name, files['profiles/90.json'].bean.name);
  assert.equal(Object.hasOwn(files['groups/7.json'], 'subscription_kind'), false);
  for (const [, group] of groups.filter(([, value]) => value.id !== 7)) assert.equal(group.subscription_kind, 'links');
  assert.equal(files['groups/7.json'].lastup, 4294967297);
  assert.match(files['groups/7.json'].info, /метаданные/);
});

test('all four archived/skip combinations and cross-group references are covered', () => {
  assert.equal(new Set(groups.map(([, group]) => `${group.archive}/${group.skip_auto_update}`)).size, 4);
  const settings = files['groups/nekobox.json'];
  assert.equal(files[`profiles/${settings.mdmbox_selected_id}.json`].gid, settings.current_group);
  assert.ok(files[`profiles/${settings.remember_id}.json`]);
  for (const [, group] of groups.filter(([, value]) => value.front_proxy_id >= 0)) {
    assert.notEqual(files[`profiles/${group.front_proxy_id}.json`].gid, group.id);
  }
});

test('profile endpoints are loopback and subscription is reserved synthetic data', () => {
  for (const [, profile] of profiles) {
    assert.equal(profile.bean.addr, '127.0.0.1');
    assert.ok(profile.bean.port > 1024 && profile.bean.port < 65536);
    assert.equal(profile.bean._v, 0);
    assert.equal(profile.bean.v, profile.type === 'http' ? -80 : 5);
  }
  assert.equal(new URL(files['groups/7.json'].url).hostname, 'subscription.invalid');
});

test('routing uses production root and preserves exact rule order/DNS strings', () => {
  const route = files[`routes_box/${files['groups/nekobox.json'].active_routing}`];
  assert.deepEqual(JSON.parse(route.custom).rules.map(rule => rule.outbound), ['proxy', 'direct']);
  assert.deepEqual(JSON.parse(route.mdmbox_rules_json).map(rule => rule.type), ['domain', 'process']);
  assert.equal(route.remote_dns, 'udp://127.0.0.1:15353');
  assert.equal(route.direct_dns, 'udp://127.0.0.1:15354');
  assert.ok(files['routes_box/SyntheticInactive']);
});

test('migration dispatch precedes QApplication and uses the global loader', () => {
  const body = entrypoint.slice(entrypoint.indexOf('int main('));
  assert.ok(body.indexOf('LegacyMigrationFixture::run(app)') < body.indexOf('QApplication app('));
  assert.match(source, /dataStore->flag_reorder = false;/);
  assert.match(source, /profileManager->LoadManager\(\);/);
  assert.doesNotMatch(source, /flag_reorder = true|removeRecursively\(|QDir::setCurrent\(/);
  assert.match(source, /FILE_ATTRIBUTE_REPARSE_POINT/);
  assert.match(source, /nNumberOfLinks != 1/);
  assert.match(source, /directory.setAutoRemove\(false\)/);
  // These source checks are not C++ compilation or guard runtime evidence.
});

test('save oracle requires full serialized state and rejects unchanged seed', () => {
  assert.match(source, /doc[.]object\(\) != it[.]value\(\)/);
  assert.ok(source.includes('if (matchesSerializedGraph(before, expectedSaved)) return fail("save-oracle-noop")'));
  assert.ok(source.includes('!matchesSerializedGraph(saved, expectedSaved)'));
  assert.ok(source.includes('!matchesSerializedGraph(before, expectedSaved)) return fail("reopen-serialization")'));
});

test('launcher arguments reject missing pins, relative paths and extra root flags', () => {
  assert.deepEqual(parseArguments(['--inspect']), { inspect: true });
  const runner = resolve('synthetic-runner.exe');
  const hash = 'a'.repeat(64);
  assert.deepEqual(parseArguments(['--runner', runner, '--sha256', hash]), { executable: runner, sha256: hash });
  for (const args of [[], ['--runner', runner], ['--runner', 'relative.exe', '--sha256', hash],
    ['--runner', runner, '--sha256', 'invalid'], ['--inspect', '--root', runner],
    ['--runner', runner, '--sha256', hash, '-flag_reorder']]) assert.throws(() => parseArguments(args));
});

test('result acceptance requires exit zero and exact marker, never a failure marker', () => {
  const good = { status: 0, signal: null, stdout: `${passMarker}\n`, stderr: '' };
  assert.equal(acceptedResult(good), true);
  for (const change of [{ status: 1 }, { signal: 'SIGTERM' }, { error: new Error('timeout') },
    { stdout: `prefix ${passMarker}` }, { stdout: '' }, { stderr: 'LEGACY_MIGRATION_FAIL' }]) {
    assert.equal(acceptedResult({ ...good, ...change }), false);
  }
});

test('checksum and hard-link checks execute only on owned synthetic files', () => {
  const root = mkdtempSync(join(tmpdir(), 'mdmbox-launch-source-test-'));
  const file = join(root, 'synthetic.bin');
  const link = join(root, 'synthetic-link.bin');
  try {
    writeFileSync(file, 'synthetic-not-an-executable');
    const hash = createHash('sha256').update(readFileSync(file)).digest('hex');
    assert.equal(checkedExecutable(file, hash), file);
    assert.throws(() => checkedExecutable(file, '0'.repeat(64)), /runner-sha256/);
    linkSync(file, link);
    assert.throws(() => checkedExecutable(file, hash), /runner-file/);
  } finally {
    try { unlinkSync(link); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    unlinkSync(file);
    rmdirSync(root);
  }
});

test('adversarial mode requires the same absolute runner and checksum pins', () => {
  const runner = resolve('synthetic-runner.exe'), hash = 'a'.repeat(64);
  assert.deepEqual(parseArguments(['--runner', runner, '--sha256', hash, '--adversarial']),
    { executable: runner, sha256: hash, adversarial: true });
  for (const args of [['--adversarial'], ['--inspect', '--adversarial'],
    ['--runner', 'relative.exe', '--sha256', hash, '--adversarial'],
    ['--runner', runner, '--sha256', hash, '--adversarial', '--root', runner],
    ['--runner', runner, '--sha256', hash, '--adversarial', '-flag_reorder']]) assert.throws(() => parseArguments(args));
});

test('observations cannot masquerade as migration acceptance or omit/repeat cases', () => {
  const lines = adversarialCases.map(name => `LEGACY_MIGRATION_EDGE_OBSERVED case=${name} acceptance=NOT_ACCEPTED`);
  const good = { status: 0, signal: null, stdout: [...lines, observationMarker, ''].join('\n'), stderr: '' };
  assert.equal(acceptedResult(good, true), true);
  assert.equal(acceptedResult(good), false);
  assert.equal(acceptedResult({ ...good, stdout: passMarker }, true), false);
  for (const stdout of [observationMarker, [...lines.slice(1), observationMarker].join('\n'),
    [...lines, lines[0], observationMarker].join('\n'), [...lines.reverse(), observationMarker].join('\n'),
    good.stdout + passMarker]) assert.equal(acceptedResult({ ...good, stdout }, true), false);
  for (const change of [{ status: 1 }, { error: new Error('timeout') }, { signal: 'SIGTERM' },
    { stderr: 'LEGACY_MIGRATION_FAIL' }]) assert.equal(acceptedResult({ ...good, ...change }, true), false);
});

test('adversarial fixture remains owned, offline and explicitly characterizes disk failure', () => {
  const edge = readFileSync(new URL('./subscription-parser/LegacyMigrationAdversarial.hpp', import.meta.url), 'utf8');
  for (const name of adversarialCases) assert.ok(edge.includes(`"${name}"`));
  assert.match(edge, /ERROR_SHARING_VIOLATION/);
  assert.match(edge, /profile->last_save_content == intended/);
  assert.match(edge, /after == before/);
  assert.match(edge, /seed != originalSeed/);
  assert.match(edge, /candidate != current/);
  assert.match(edge, /wrongCorpus\[3\] = testCase/);
  assert.match(edge, /LEGACY_MIGRATION_FAIL edge-not-synthetic/);
  assert.match(edge, /guardedCandidate != current/);
  assert.match(edge, /args.size\(\) != 7/);
  assert.match(edge, /directory.setAutoRemove\(false\)/);
  assert.match(edge, /!cleanup\(workspace, token, removed\(testCase\)\)/);
  assert.doesNotMatch(edge, /removeRecursively\(|flag_reorder = true|QDir::setCurrent\(/);
  assert.match(source, /role != "candidate" \|\| absent != QSet<QString>\{"profiles\/205.json"\}/);
  const main = entrypoint.slice(entrypoint.indexOf('int main('));
  assert.ok(main.indexOf('LegacyMigrationAdversarial::run(app)') < main.indexOf('QApplication app('));
});
