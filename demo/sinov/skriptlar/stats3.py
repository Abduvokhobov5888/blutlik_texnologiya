"""III bob uchun qo'shimcha statistika (analyze.py natijalariga qo'shimcha).
Foydalanish: python stats3.py <Sinov_papkasi>  ->  natijalar/tahlil/ch3.json
"""
import json, os, sys, glob, csv, statistics, collections

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
RES = os.path.join(ROOT, 'natijalar'); IMG = os.path.join(RES, 'images'); OUT = os.path.join(RES, 'tahlil')
SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']
RANK = {s: i for i, s in enumerate(SEV)}

def cve(i, rel=()):
    if i.upper().startswith('CVE-'): return i.upper()
    for r in rel or []:
        x = r.get('id', '') if isinstance(r, dict) else str(r)
        if x.upper().startswith('CVE-'): return x.upper()
    return i.upper()

def load(p):
    with open(p, encoding='utf-8-sig') as f: return json.load(f)

def trivy(name, run=1):
    p = os.path.join(IMG, f'trivy_{name}_run{run}.json')
    if not os.path.exists(p) or os.path.getsize(p) == 0: return None
    d = load(p); out = {}
    for r in d.get('Results', []) or []:
        for v in r.get('Vulnerabilities') or []:
            c = cve(v['VulnerabilityID'])
            out.setdefault(c, []).append({'type': r.get('Type'), 'status': v.get('Status'), 'sev': (v.get('Severity') or 'UNKNOWN').upper(),
                                          'fix': bool(v.get('FixedVersion')), 'pkg': v.get('PkgName')})
    return out, d.get('Metadata', {}).get('OS', {})

def grype(name, run=1):
    p = os.path.join(IMG, f'grype_{name}_run{run}.json')
    if not os.path.exists(p) or os.path.getsize(p) == 0: return None
    d = load(p); out = {}
    for m in d.get('matches', []):
        v = m['vulnerability']; a = m['artifact']
        c = cve(v['id'], m.get('relatedVulnerabilities'))
        sev = (v.get('severity') or 'Unknown').upper()
        out.setdefault(c, []).append({'type': a.get('type'), 'state': (v.get('fix') or {}).get('state'), 'sev': sev,
                                      'fix': (v.get('fix') or {}).get('state') == 'fixed', 'ns': v.get('namespace'), 'pkg': a.get('name'),
                                      'cpe': (v.get('namespace') or '').startswith('nvd:cpe') or a.get('type') == 'binary'})
    return out, d.get('distro', {})

def maxsev(lst):
    return min((x['sev'] for x in lst), key=lambda s: RANK.get(s, 9))

GROUPS = {'A': ['debian:12-slim', 'ubuntu:24.04', 'python:3.12-slim', 'python:3.12-alpine'],
          'B': ['alpine:3.18', 'alpine:3.20', 'debian:11-slim', 'ubuntu:20.04', 'centos:7', 'python:3.9-slim', 'node:16-alpine'],
          'C': ['nginx:1.21', 'postgres:13', 'redis:6.2'],
          'D': ['bkimminich/juice-shop:v15.0.0']}
imgs = [i for g in GROUPS.values() for i in g]
rows = []; pairs = {'T': set(), 'G': set(), 'Tc': set(), 'Gc': set()}
gpairs = {g: {'T': set(), 'G': set()} for g in GROUPS}
cause = collections.Counter()
for img in imgs:
    name = img.replace('/', '_').replace(':', '_')
    t = trivy(name); g = grype(name)
    row = {'image': img, 'group': [k for k, v in GROUPS.items() if img in v][0]}
    if g:
        G, dist = g
        row.update({'g_n': len(G), 'g_fix': sum(1 for c in G if any(x['fix'] for x in G[c])),
                    'g_cpe': sum(1 for c in G if all(x['cpe'] for x in G[c]))})
        for s in ['CRITICAL', 'HIGH']: row['g_' + s[:4].lower()] = sum(1 for c in G if maxsev(G[c]) == s)
        row['g_det'] = all(set((grype(name, r) or ({}, {}))[0]) == set(G) for r in (2, 3))
    if t:
        T, os_ = t
        row.update({'t_n': len(T), 't_fix': sum(1 for c in T if any(x['fix'] for x in T[c])), 'eosl': bool(os_.get('EOSL')),
                    'os': f"{os_.get('Family', '')} {os_.get('Name', '')}".strip()})
        for s in ['CRITICAL', 'HIGH']: row['t_' + s[:4].lower()] = sum(1 for c in T if maxsev(T[c]) == s)
        row['t_det'] = all(set((trivy(name, r) or ({}, {}))[0]) == set(T) for r in (2, 3))
    if t and g:
        A, B = set(T), set(G)
        row.update({'common': len(A & B), 'only_t': len(A - B), 'only_g': len(B - A),
                    'j': len(A & B) / len(A | B) if A | B else 1.0,
                    'c_tg': len(A & B) / len(A) if A else None, 'c_gt': len(A & B) / len(B) if B else None})
        # taqqoslanadigan qism: Grype CPE/binary va Trivy CVE bo'lmagan identifikatorlari chiqarib tashlanadi
        Ac = {c for c in A if c.startswith('CVE-')}; Bc = {c for c in B if not all(x['cpe'] for x in G[c])}
        row['j_core'] = len(Ac & Bc) / len(Ac | Bc) if Ac | Bc else 1.0
        for c in A: pairs['T'].add((img, c)); gpairs[row['group']]['T'].add(c + img)
        for c in B: pairs['G'].add((img, c)); gpairs[row['group']]['G'].add(c + img)
        for c in Ac: pairs['Tc'].add((img, c))
        for c in Bc: pairs['Gc'].add((img, c))
        # farqlar sabablari
        for c in B - A:
            x = G[c]
            if all(y['cpe'] for y in x): cause['G: binar fayl / CPE bo‘yicha moslik'] += 1
            elif all(y['state'] == 'wont-fix' for y in x): cause['G: «tuzatilmaydi» (wont-fix) holatidagi yozuvlar'] += 1
            else: cause['G: boshqa'] += 1
        for c in A - B:
            x = T[c]
            if not c.startswith('CVE-'): cause['T: CVE bo‘lmagan identifikatorlar (TEMP/DSA/DLA/GHSA)'] += 1
            elif any(y['type'] == 'gobinary' for y in x): cause['T: Go binar fayllari (stdlib)'] += 1
            elif os_.get('Family') == 'debian' and str(os_.get('Name', '')).startswith('11') and c.startswith('CVE-2026-'): cause['T: Debian 11 bo‘yicha 2026-yilgi yangi yozuvlar'] += 1
            else: cause['T: boshqa'] += 1
    rows.append(row)

def jac(a, b): return len(a & b) / len(a | b) if a | b else 1.0
overall = {'t': len(pairs['T']), 'g': len(pairs['G']), 'common': len(pairs['T'] & pairs['G']), 'j': jac(pairs['T'], pairs['G']),
           'j_core': jac(pairs['Tc'], pairs['Gc']), 'tc': len(pairs['Tc']), 'gc': len(pairs['Gc']), 'common_core': len(pairs['Tc'] & pairs['Gc'])}
groups = {k: {'t': len(v['T']), 'g': len(v['G']), 'common': len(v['T'] & v['G']), 'j': jac(v['T'], v['G'])} for k, v in gpairs.items()}

# vaqt
timing = collections.defaultdict(dict)
tf = os.path.join(RES, 'timings.csv')
rows_t = list(csv.DictReader(open(tf, encoding='utf-8-sig'), delimiter=';'))
st = [i for i, r in enumerate(rows_t) if r['tool'].lstrip('﻿').strip() == 'checkov' and r['run'].strip() == '1']
rows_t = rows_t[st[-1]:] if st else rows_t
for r in rows_t:
    timing[(r['tool'].lstrip('﻿').strip(), r['target'].strip())][r['run'].strip()] = (float(r['seconds']), r['exitcode'].strip())
tim = []
for (tool, target), d in sorted(timing.items()):
    v = [d[k][0] for k in sorted(d)]
    tim.append({'tool': tool, 'target': target, 'runs': v, 'mean': statistics.mean(v), 'sd': statistics.stdev(v) if len(v) > 1 else 0,
                'warm': statistics.mean(v[1:]) if len(v) > 1 else v[0], 'codes': [d[k][1] for k in sorted(d)]})
summ = load(os.path.join(OUT, 'summary.json'))
json.dump({'images': rows, 'overall': overall, 'groups': groups, 'causes': dict(cause), 'timing': tim,
           'iac': summ['iac_summary'], 'iac_overlap': summ['iac_overlap'], 'missed_by_all': summ['missed_by_all'], 'db': summ.get('db_info')},
          open(os.path.join(OUT, 'ch3.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(json.dumps({'overall': overall, 'groups': groups, 'causes': cause}, ensure_ascii=False, indent=1))
for r in rows: print(r)
