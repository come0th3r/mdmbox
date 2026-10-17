import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstatSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
export const passMarker = 'LEGACY_MIGRATION_VALID_ROOT_REOPEN_PASS children=2 guards=4 seed_files=15';
export const observationMarker = 'LEGACY_MIGRATION_ADVERSARIAL_OBSERVATIONS_COMPLETE cases=11 children=24 guards=55 persistence=atomic-v1 load=preserve-v1 acceptance=NOT_ACCEPTED';
export const adversarialCases = ['malformed-profile', 'invalid-type', 'malformed-group', 'orphan-profile',
  'duplicate-id', 'duplicate-order', 'write-lock', 'invalid-bean', 'all-invalid-profiles',
  'max-invalid-profile', 'all-invalid-groups'];

export function inspectFixture() {
  const source = readFileSync(join(repository, 'test/subscription-parser/LegacyMigrationFixture.hpp'), 'utf8');
  const start = 'SeedJson[] = R"fixture(';
  const end = ')fixture";';
  const offset = source.indexOf(start);
  const finish = source.indexOf(end, offset + start.length);
  if (offset < 0 || finish < 0) throw new Error('missing-seed');
  const files = JSON.parse(source.slice(offset + start.length, finish));
  const entrypoint = readFileSync(join(repository, 'test/subscription-parser/main.cpp'), 'utf8');
  return { files, source, entrypoint };
}

export function parseArguments(args) {
    if (args.length === 1 && args[0] === '--inspect') return { inspect: true };
  const adversarial = args.length === 5 && args[4] === '--adversarial';
  if (adversarial) args = args.slice(0, 4);
  if (args.length !== 4 || args[0] !== '--runner' || args[2] !== '--sha256' ||
      !isAbsolute(args[1]) || !/^[0-9a-f]{64}$/i.test(args[3])) throw new Error('arguments');
  return { executable: args[1], sha256: args[3].toLowerCase(), ...(adversarial ? { adversarial: true } : {}) };
}

export function checkedExecutable(path, expectedHash) {
  const full = resolve(path);
  for (let current = full; ; current = dirname(current)) {
    const info = lstatSync(current);
    if (info.isSymbolicLink()) throw new Error('runner-link');
    const canonical = realpathSync(current);
    const same = process.platform === 'win32' ? canonical.toLowerCase() === current.toLowerCase() : canonical === current;
    if (!same) throw new Error('runner-alias');
    if (dirname(current) === current) break;
  }
  const stat = lstatSync(full);
  if (!stat.isFile() || stat.nlink !== 1) throw new Error('runner-file');
  const actual = createHash('sha256').update(readFileSync(full)).digest('hex');
  if (actual !== expectedHash) throw new Error('runner-sha256');
  return full;
}

export function acceptedResult(result, adversarial = false) {
  const lines = String(result.stdout).split(/\r?\n/);
  const marker = adversarial ? observationMarker : passMarker;
  const expected = adversarial ? [...adversarialCases.map(name =>
    `LEGACY_MIGRATION_EDGE_OBSERVED case=${name} acceptance=NOT_ACCEPTED`), marker] : [marker];
  const fixtureLines = lines.filter(line => line.startsWith('LEGACY_MIGRATION_'));
  return !result.error && result.signal == null && result.status === 0 &&
    fixtureLines.length === expected.length && fixtureLines.every((line, i) => line === expected[i]) &&
    !String(result.stdout).includes('LEGACY_MIGRATION_FAIL') &&
    !String(result.stderr).includes('LEGACY_MIGRATION_FAIL');
}

export function main(args) {
  let cwd;
  try {
    const options = parseArguments(args);
    const { files } = inspectFixture();
    if (Object.keys(files).length !== 13) throw new Error('seed-count');
    if (options.inspect) {
      console.log('LEGACY_MIGRATION_SOURCE_INSPECTION_ONLY json_files=13 runtime=NOT_RUN');
      return 0;
    }
    const executable = checkedExecutable(options.executable, options.sha256);
    // Even an accidental fixture fallthrough must not inherit a real app root.
    cwd = mkdtempSync(join(tmpdir(), 'mdmbox-migration-launch-'));
    const result = spawnSync(executable, [options.adversarial ? '--legacy-migration-adversarial' : '--legacy-migration'], {
      cwd, shell: false, encoding: 'utf8', timeout: options.adversarial ? 600000 : 240000, maxBuffer: 1024 * 1024,
      env: { ...process.env, QT_QPA_PLATFORM: 'offscreen' },
    });
    // Do not forward raw application diagnostics or persisted profile data.
    if (!acceptedResult(result, options.adversarial)) throw new Error('runner-result');
    if (readdirSync(cwd).length !== 0) throw new Error('launcher-cwd-mutated');
    rmdirSync(cwd);
    cwd = undefined;
    if (options.adversarial) {
      for (const name of adversarialCases) console.log(`LEGACY_MIGRATION_EDGE_OBSERVED case=${name} acceptance=NOT_ACCEPTED`);
      console.log(observationMarker);
    } else console.log(passMarker);
    return 0;
  } catch {
    // Non-empty or unvalidated directories are never recursively removed.
    if (cwd) {
      try { if (readdirSync(cwd).length === 0) rmdirSync(cwd); } catch { /* retain */ }
    }
    console.error('LEGACY_MIGRATION_LAUNCH_FAIL runtime=NOT_ACCEPTED');
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
