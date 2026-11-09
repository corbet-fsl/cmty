import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const corbetSource = /^git\+https:\/\/(?:github\.com|git\.corbet\.ch)\/(?:corbet-(?:foss|fsl|libre)|cmtymt)\//;

function resolvedPackages(metadata) {
  if (!metadata.resolve || !Array.isArray(metadata.resolve.nodes)) {
    throw new Error('Missing resolved dependency graph');
  }
  const packages = new Map();
  for (const pkg of metadata.packages) {
    if (typeof pkg.id !== 'string' || packages.has(pkg.id)) {
      throw new Error('Missing or duplicated package ID');
    }
    packages.set(pkg.id, pkg);
  }
  const nodes = new Map();
  for (const node of metadata.resolve.nodes) {
    if (!packages.has(node.id) || nodes.has(node.id)) {
      throw new Error('Unknown or duplicated resolved package ID');
    }
    nodes.set(node.id, node);
  }
  if (nodes.size !== packages.size) throw new Error('Incomplete resolved package graph');
  if (metadata.resolve.root !== null && !nodes.has(metadata.resolve.root)) {
    throw new Error('Unknown resolved root package');
  }
  if (!Array.isArray(metadata.workspace_members)
      || metadata.workspace_members.some(id => !nodes.has(id))) {
    throw new Error('Unknown or missing resolved workspace members');
  }
  return [...nodes.values()].map(node => {
    const pkg = packages.get(node.id);
    if (!Array.isArray(node.deps) || !Array.isArray(node.dependencies)) {
      throw new Error('Missing resolved dependency edges');
    }
    const edgeIDs = new Set(node.deps.map(edge => edge.pkg));
    if (edgeIDs.size !== new Set(node.dependencies).size
        || node.dependencies.some(id => !edgeIDs.has(id))) {
      throw new Error('Inconsistent resolved dependency edges');
    }
    const declarations = [];
    for (const edge of node.deps) {
      const selected = packages.get(edge.pkg);
      if (!selected || !nodes.has(edge.pkg) || !Array.isArray(edge.dep_kinds)
          || edge.dep_kinds.length === 0) {
        throw new Error('Unknown or incomplete resolved dependency edge');
      }
      for (const kind of edge.dep_kinds) {
        if (![null, 'dev', 'build'].includes(kind.kind)
            || (kind.target !== null && typeof kind.target !== 'string')) {
          throw new Error('Invalid resolved dependency kind');
        }
        const matching = pkg.dependencies.filter(dependency =>
          dependency.name === selected.name
          && (dependency.rename !== null && dependency.rename !== undefined
            ? dependency.rename.replaceAll('-', '_') === edge.name
            : selected.targets?.some(target =>
              target.kind.some(value => ['lib', 'rlib', 'dylib', 'cdylib', 'staticlib', 'proc-macro'].includes(value))
              && target.name.replaceAll('-', '_') === edge.name))
          && dependency.kind === kind.kind && dependency.target === kind.target);
        if (matching.length === 0) throw new Error('Missing selected dependency declaration');
        if (matching.some(dependency =>
          (corbetSource.test(dependency.source ?? '') || corbetSource.test(selected.source ?? ''))
          && dependency.source !== selected.source?.split('#')[0])) {
          throw new Error('Mismatched selected dependency source');
        }
        declarations.push(...matching);
      }
    }
    return { ...pkg, dependencies: declarations };
  });
}

function checkSource(source, resolved, name, issuers) {
  const issuer = issuers.get(name);
  if (issuer && source === (resolved ? issuer.resolved : issuer.declaration)) return;
  const url = new URL(source.slice(4));
  const main = url.searchParams.toString() === 'branch=main';
  if (!main || (resolved && !/^#[a-f0-9]{40}$/.test(url.hash))) {
    throw new Error(`Expected main and a complete resolved revision: ${source}`);
  }
}

export function checkPins(metadata) {
  const selected = resolvedPackages(metadata);
  // Keep original issuer policy in the resolved-lock validator. The existing
  // metadata checks still enforce all main selectors and singleton identities.
  const policy = fileURLToPath(new URL('./check-first-party.py', import.meta.url));
  const issuers = new Map(JSON.parse(execFileSync('python3', [policy, '--metadata-issuers'], {
    input: JSON.stringify({ packages: selected }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  })).map(issuer => [issuer.name, issuer]));
  const names = new Set(['crlt']);
  for (const pkg of selected) {
    if (corbetSource.test(pkg.source ?? '') || issuers.has(pkg.name)) {
      names.add(pkg.name);
      checkSource(pkg.source, true, pkg.name, issuers);
    }
    // Only selected dep IDs/kinds expose an upstream declaration in this graph.
    // Unused upstream dev/optional declarations stay under their owner's policy.
    for (const dependency of pkg.dependencies) {
      if (corbetSource.test(dependency.source ?? '')) {
        checkSource(dependency.source, false, dependency.name, issuers);
      }
    }
  }
  for (const name of names) {
    const packages = selected.filter(pkg => pkg.name === name);
    if (packages.length !== 1 || !corbetSource.test(packages[0].source ?? '')) {
      throw new Error(`Missing, invalid or duplicated Corbet dependency: ${name}`);
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  checkPins(JSON.parse(readFileSync(process.argv[2], 'utf8')));
  console.log('Corbet dependencies resolve once each to a complete source revision');
}
