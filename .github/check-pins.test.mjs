import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkPins } from './check-pins.mjs';

const revision = '6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc';
const older = '9c076b1e4050529406df27533e12c8e0dd1fc0db';
const source = (name, rev = revision) =>
  `git+https://git.corbet.ch/corbet-libre/${name}?branch=main#${rev}`;
let nextID = 0;
const pkg = (name, source = null, dependencies = []) => ({
  id: `${name}:${nextID++}`, name, source,
  targets: [{ kind: ['lib'], name: name.replaceAll('-', '_') }],
  dependencies: dependencies.map(dependency => ({
    name: dependency.name ?? new URL(dependency.source.slice(4)).pathname.split('/').at(-1).replace(/\.git$/, ''),
    kind: null, target: null, ...dependency,
  })),
});
const metadata = (...packages) => ({
  packages,
  workspace_members: packages.length ? [packages[0].id] : [],
  resolve: {
    root: packages[0]?.id ?? null,
    nodes: packages.map(owner => {
      const deps = owner.dependencies.map(dependency => {
        const target = packages.find(candidate => candidate.name === dependency.name);
        return {
          name: (dependency.rename ?? dependency.name).replaceAll('-', '_'),
          pkg: target?.id ?? 'missing',
          dep_kinds: [{ kind: dependency.kind, target: dependency.target }],
        };
      });
      return { id: owner.id, deps, dependencies: [...new Set(deps.map(dep => dep.pkg))], features: [] };
    }),
  },
});
const graph = (...packages) => metadata(pkg('crbk'), pkg('crlt', source('crlt')), ...packages);

test('accept a single revision per leaf and unrelated registry duplicates', () => {
  checkPins(graph(pkg('serde'), pkg('thiserror'), pkg('thiserror')));
});

test('reject duplicate direct and transitive Corbet packages', () => {
  assert.throws(() => checkPins(graph(pkg('crlt', source('crlt', older)))), /duplicated/);
  assert.throws(() => checkPins(graph(
    pkg('csgn', source('csgn')), pkg('csgn', source('csgn', older)),
  )), /duplicated/);
  assert.throws(() => checkPins(graph(pkg('crlt'))), /duplicated/);
});

test('reject other branches, tags, unqualified and abbreviated revisions', () => {
  for (const query of ['branch=develop', 'tag=v1', '', `rev=${revision.slice(0, 7)}`]) {
    const floating = `git+https://github.com/corbet-foss/csgn?${query}#${revision}`;
    assert.throws(() => checkPins(graph(pkg('csgn', floating))), /Expected main/);
  }
});

test('reject every matching transitive revision pin', () => {
  const pinned = `git+https://github.com/corbet-foss/csgn?rev=${revision}#${revision}`;
  assert.throws(() => checkPins(graph(pkg('csgn', pinned))), /Expected main/);
  assert.throws(() => checkPins(graph(pkg('csgn', source('csgn'), [
    { source: pinned.split('#')[0] },
  ]))), /Expected main|Mismatched/);
});

test('accept main declarations with a unique complete resolution', () => {
  const dependency = { source: 'git+https://github.com/corbet-foss/cpns?branch=main' };
  checkPins(graph(
    pkg('cgrd', source('cgrd'), [dependency]),
    pkg('cpns', `git+https://github.com/corbet-foss/cpns?branch=main#${revision}`),
  ));
});

test('require the crlt Git dependency', () => {
  assert.throws(() => checkPins(metadata(pkg('crbk'))), /Missing/);
  assert.throws(() => checkPins(metadata(pkg('crbk'), pkg('crlt'))), /invalid/);
});


test('canonical sources reject pins and mixed-origin duplicates', () => {
  const canonical = source('crlt').replace('github.com', 'git.corbet.ch');
  checkPins(metadata(pkg('crlt', canonical)));
  assert.throws(() => checkPins(graph(pkg('crlt', canonical))), /duplicated/);
  assert.throws(() => checkPins(metadata(pkg('crlt', canonical.replace('branch=main', `rev=${revision}`)))), /Expected main/);
});

test('accept main issuer resolutions and transitive declarations', () => {
  const issuers = ['cmbl', 'cmmr'].map(name => ({
    ...pkg(name, `git+https://git.corbet.ch/corbet-libre/${name}.git?branch=main#${revision}`),
    version: '0.1.0',
  }));
  const dependencies = issuers.map(owner => ({
    name: owner.name, source: owner.source.split('#')[0],
  }));
  checkPins(graph(pkg('cblc', source('cblc'), dependencies), ...issuers));
});

test('reject retired owner substitutions, aliases, versions and duplicate identities', () => {
  for (const name of ['cmbl', 'cmmr']) {
    const original = `git+https://git.corbet.ch/corbet-libre/${name}.git?branch=main#${revision}`;
    const owner = { ...pkg(name, original), version: '0.1.0' };
    for (const bad of [
      ...[
        original.replace('branch=main', 'branch=v01'),
        original.replace('branch=main', 'branch=other'),
        original.replace('branch=main', 'tag=v01'),
        original.replace('branch=main', `rev=${revision}`),
        original.replace('branch=main', 'branch=main&branch=main'),
        original.replace('branch=main', 'branch=main&extra='),
        original.replace(`#${revision}`, '#short'),
        original.replace(`#${revision}`, `#${revision.toUpperCase()}`),
      ].map(badSource => ({ ...owner, source: badSource })),
    ]) assert.throws(() => checkPins(graph(bad)));
    assert.throws(() => checkPins(graph(owner, owner)), /duplicated/);
    assert.throws(() => checkPins(graph(owner, pkg(name))), /duplicated/);
    checkPins(graph(owner));
  }
});

test('reject altered and unresolved original transitive selectors', () => {
  const name = 'cmbl';
  const declaration = `git+https://git.corbet.ch/corbet-foss/${name}.git?branch=v01`;
  const owner = { ...pkg(name, `${declaration}#${revision}`), version: '0.1.0' };
  for (const raw of [
    declaration.replace('v01', 'v02'),
    declaration.replace('v01', 'v%30%31'),
    `${declaration}&branch=v01`,
    `${declaration}#${revision}`,
    declaration.replace('.git?', '?'),
    declaration.replace('git.corbet.ch', 'github.com'),
    'registry+https://example.test/index',
    null,
  ]) assert.throws(() => checkPins(graph(
    owner, pkg('cblc', source('cblc'), [{ name, source: raw }]),
  )));
  assert.throws(() => checkPins(graph(
    pkg('cblc', source('cblc'), [{ name, source: declaration }]),
  )));
  assert.throws(() => checkPins(graph(
    owner, pkg('cblc', source('cblc'), [{ name: 'other', source: declaration }]),
  )));
});

test('ignore inactive upstream dev and optional declarations, not selected edges', () => {
  const inactive = pkg('cgbl', source('cgbl'), [
    { name: 'cchr', source: source('cchr').split('#')[0].replace('branch=main', 'branch=v01'), kind: 'dev' },
    { name: 'cvlk', source: source('cvlk').split('#')[0].replace('branch=main', 'branch=v01'), optional: true },
  ]);
  const unused = graph(inactive);
  const node = unused.resolve.nodes.find(value => value.id === inactive.id);
  node.deps = []; node.dependencies = [];
  checkPins(unused);
  const activated = pkg('cchr', source('cchr').replace('branch=main', 'branch=v01'));
  const activeOwner = { ...inactive, dependencies: [inactive.dependencies[0]] };
  assert.throws(() => checkPins(graph(activeOwner, activated)), /Expected main/);
});

test('retain active workspace dev and build selectors, including renamed targets', () => {
  for (const kind of ['dev', 'build', null]) {
    const dependency = {
      name: 'cpns', rename: 'renamed-owner', kind, target: 'cfg(unix)',
      source: source('cpns').split('#')[0],
    };
    const owner = pkg('workspace', null, [dependency]);
    checkPins(metadata(owner, pkg('crlt', source('crlt')), pkg('cpns', source('cpns'))));
    const bad = { ...dependency, source: dependency.source.replace('branch=main', 'branch=v01') };
    assert.throws(() => checkPins(metadata(
      pkg('workspace', null, [bad]), pkg('crlt', source('crlt')),
      pkg('cpns', source('cpns').replace('branch=main', 'branch=v01')),
    )), /Expected main/);
  }
});

test('match an original library name distinct from its package name', () => {
  const library = pkg('crlt', source('crlt'));
  library.targets[0].name = 'transaction_owner';
  const value = metadata(pkg('workspace', null, [
    { name: 'crlt', source: source('crlt').split('#')[0] },
  ]), library);
  value.resolve.nodes[0].deps[0].name = 'transaction_owner';
  checkPins(value);
});

test('refuse absent, incomplete, contradictory and unknown resolved graph data', () => {
  const mutations = [
    value => { delete value.resolve; },
    value => { value.resolve.nodes.pop(); },
    value => { value.resolve.nodes[0].id = 'unknown'; },
    value => { value.resolve.root = 'unknown'; },
    value => { value.workspace_members.push('unknown'); },
    value => { value.packages[1].id = value.packages[0].id; },
    value => { delete value.resolve.nodes[0].deps; },
    value => { value.resolve.nodes[0].dependencies.push('unknown'); },
    value => {
      value.resolve.nodes[0].dependencies = ['unknown'];
      value.resolve.nodes[0].deps = [{ pkg: 'unknown', name: 'x', dep_kinds: [{ kind: null, target: null }] }];
    },
  ];
  for (const mutate of mutations) {
    const value = graph(); mutate(value);
    assert.throws(() => checkPins(value));
  }
  for (const mutate of [
    value => { value.resolve.nodes[2].deps[0].dep_kinds = []; },
    value => { value.resolve.nodes[2].deps[0].dep_kinds[0].kind = 'other'; },
    value => { value.resolve.nodes[2].deps[0].dep_kinds[0].target = 7; },
    value => { value.resolve.nodes[2].deps[0].name = 'other'; },
    value => { value.resolve.nodes[2].deps[0].dep_kinds[0].kind = 'dev'; },
    value => { value.packages[2].dependencies[0].source = source('cpns').split('#')[0]; },
  ]) {
    const value = graph(pkg('caller', null, [{ name: 'crlt', source: source('crlt').split('#')[0] }]));
    mutate(value); assert.throws(() => checkPins(value));
  }
});
