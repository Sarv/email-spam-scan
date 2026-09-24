#!/usr/bin/env node
/**
 * Audit the protected-brand list against the registries and the DNS.
 *
 * `PROTECTED_BRANDS` decides which domains may wear a brand's name
 * unchallenged, so a WRONG domain in it is the dangerous direction: an entry
 * nobody owns can be registered by an attacker tomorrow, and from then on the
 * brand rule waves their mail through. This script asks, for every listed
 * domain, the questions that catch that:
 *
 *   - Is it registered? (the registry's RDAP record, through `/age`; for
 *     the many ccTLDs that publish no RDAP, whether the name is delegated at
 *     all). Unregistered is CRITICAL: anybody can buy it.
 *   - Does it publish SPF? A domain a brand really sends mail from does.
 *   - Does it publish DMARC, and with what policy? Brands phishing targets
 *     almost all enforce (`quarantine` or `reject`); `none` or nothing is
 *     worth a second look.
 *
 * A missing record is a WARNING, not proof of anything — a brand may own a
 * domain it never sends from — and `--strict` turns warnings into failures.
 * The exit code is non-zero on any CRITICAL, so CI can run this on a schedule
 * and on every pull request that touches the list.
 *
 * It imports the BUILT package by its own name (`pnpm build` first), exactly
 * as a consumer would, so what is audited is what ships.
 *
 * PASS `--resolver` ON AN OFFICE OR HOME NETWORK. Brands publish dozens of TXT
 * records at the apex (every SaaS verification token they ever added), and
 * some resolvers answer only the first twenty without saying so. The SPF
 * record is then simply missing from the answer, and a perfectly configured
 * brand is reported as publishing none. `--resolver 1.1.1.1` asks a resolver
 * that returns the whole set.
 *
 *   node scripts/verify-brands.mjs [--strict] [--brand <id>] [--resolver <ip>]
 */
import { Resolver } from 'node:dns/promises';

import { fetchRdapBootstrap, lookupDomainAge } from '@sarv-in/mailguard/age';
import { PROTECTED_BRANDS } from '@sarv-in/mailguard/identity';

const args = process.argv.slice(2);
const strict = args.includes('--strict');
const only = args.includes('--brand') ? args[args.indexOf('--brand') + 1] : null;
const resolver = new Resolver({ timeout: 8_000, tries: 2 });
if (args.includes('--resolver')) resolver.setServers([args[args.indexOf('--resolver') + 1]]);

/** TXT records at a name; [] when the name or the record type does not exist, null when the lookup failed. */
async function txt(name) {
  try {
    return (await resolver.resolveTxt(name)).map((chunks) => chunks.join(''));
  } catch (cause) {
    if (cause?.code === 'ENOTFOUND' || cause?.code === 'ENODATA') return [];
    return null;
  }
}

/** Whether the name is delegated: true with nameservers, false for NXDOMAIN, null when the lookup failed. */
async function delegated(name) {
  try {
    return (await resolver.resolveNs(name)).length > 0;
  } catch (cause) {
    if (cause?.code === 'ENOTFOUND') return false;
    return cause?.code === 'ENODATA' ? true : null;
  }
}

async function audit(domain, bootstrap) {
  const [age, root, dmarc, ns] = await Promise.all([
    lookupDomainAge(domain, { bootstrap }),
    txt(domain),
    txt(`_dmarc.${domain}`),
    delegated(domain),
  ]);
  const spf = root === null ? null : root.some((record) => /^v=spf1(?:\s|$)/i.test(record.trim()));
  const dmarcRecord =
    dmarc === null ? null : (dmarc.find((record) => /^v=DMARC1\s*;/i.test(record.trim())) ?? '');
  const policy = dmarcRecord
    ? (/(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(dmarcRecord)?.[1]?.toLowerCase() ?? '?')
    : dmarcRecord;

  const problems = [];
  if (age.status === 'not-found')
    problems.push({ level: 'CRITICAL', text: 'not registered — anybody can register it' });
  else if (age.status !== 'ok' && ns === false)
    problems.push({ level: 'CRITICAL', text: 'the name does not resolve — is it registered?' });
  else if (age.status !== 'ok' && ns === null)
    problems.push({ level: 'note', text: `registration unknown (${age.detail})` });
  if (spf === null) problems.push({ level: 'note', text: 'SPF lookup failed' });
  else if (!spf) problems.push({ level: 'WARN', text: 'no SPF record' });
  if (policy === null) problems.push({ level: 'note', text: 'DMARC lookup failed' });
  else if (policy === '') problems.push({ level: 'WARN', text: 'no DMARC record' });
  else if (policy === 'none') problems.push({ level: 'WARN', text: 'DMARC p=none' });

  return {
    domain,
    registered:
      age.status === 'ok'
        ? new Date(age.registered * 1000).toISOString().slice(0, 10)
        : ns
          ? 'delegated'
          : age.status,
    registrar: age.registrar ?? '',
    spf: spf === null ? '?' : spf ? 'yes' : 'NO',
    dmarc: policy === null ? '?' : policy === '' ? 'NO' : policy,
    problems,
  };
}

/** Run `work` over `items`, at most `width` at a time, keeping input order. */
async function pool(items, width, work) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(width, items.length) }, async () => {
      while (next < items.length) {
        const index = next++;
        results[index] = await work(items[index]);
      }
    }),
  );
  return results;
}

const brands = PROTECTED_BRANDS.filter((brand) => only === null || brand.id === only);
if (brands.length === 0) {
  console.error(`No brand with id "${only}".`);
  process.exit(2);
}
const bootstrap = await fetchRdapBootstrap();
if (!bootstrap) {
  console.error('Could not read the IANA RDAP bootstrap registry; registration cannot be checked.');
}

const jobs = brands.flatMap((brand) => brand.domains.map((domain) => ({ brand, domain })));
// Four at a time: registries rate-limit RDAP, and a burst of 130 from one
// address is the fastest way to be told to come back later.
const rows = await pool(jobs, 4, async ({ brand, domain }) => ({
  brand: brand.id,
  ...(await audit(domain, bootstrap)),
}));

const pad = (value, width) => String(value).padEnd(width);
console.log(
  `${pad('brand', 18)}${pad('domain', 28)}${pad('registered', 13)}${pad('spf', 5)}${pad('dmarc', 12)}registrar`,
);
for (const row of rows) {
  console.log(
    `${pad(row.brand, 18)}${pad(row.domain, 28)}${pad(row.registered, 13)}${pad(row.spf, 5)}${pad(row.dmarc, 12)}${row.registrar}`,
  );
}

const flagged = rows.flatMap((row) =>
  row.problems.map((problem) => ({ ...problem, where: `${row.brand} ${row.domain}` })),
);
const count = (level) => flagged.filter((problem) => problem.level === level).length;
console.log('');
for (const level of ['CRITICAL', 'WARN', 'note']) {
  for (const problem of flagged.filter((p) => p.level === level))
    console.log(`${pad(level, 9)}${pad(problem.where, 46)}${problem.text}`);
}
console.log(
  `\n${jobs.length} domains across ${brands.length} brands: ${count('CRITICAL')} critical, ${count('WARN')} warnings, ${count('note')} notes.`,
);

process.exitCode = count('CRITICAL') > 0 || (strict && count('WARN') > 0) ? 1 : 0;
