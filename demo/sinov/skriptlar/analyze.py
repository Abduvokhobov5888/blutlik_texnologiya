"""III bob uchun natijalarni tahlil qilish skripti.
Foydalanish: python analyze.py <Sinov_papkasi>
Natija: <Sinov>/natijalar/tahlil/ papkasida CSV, JSON va PNG fayllar.
"""
import csv, json, os, re, sys, glob, statistics, itertools
from collections import defaultdict, Counter

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
RES = os.path.join(ROOT, 'natijalar')
OUT = os.path.join(RES, 'tahlil')
os.makedirs(OUT, exist_ok=True)

def norm(p):
    return (p or '').replace('\\', '/').lstrip('./').lower()

# ---------------- Ground truth ----------------
GT = []
with open(os.path.join(ROOT, 'ground_truth.csv'), encoding='utf-8') as f:
    for r in csv.DictReader(f, delimiter=';'):
        GT.append(r)

# Terraform faylida qator raqami -> resurs nomi
def tf_line_map(path):
    m = {}
    full = os.path.join(ROOT, 'iac', path)
    if not os.path.exists(full):
        return m
    cur = None
    for i, line in enumerate(open(full, encoding='utf-8'), 1):
        mm = re.match(r'\s*(resource|provider|variable|data)\s+"([^"]+)"(?:\s+"([^"]+)")?', line)
        if mm and not line.startswith(' '):
            cur = mm.group(3) or mm.group(2)
        m[i] = cur
    return m
LINEMAP = {p: tf_line_map(p) for p in set([g['insecure_file'] for g in GT] + [g['secure_file'] for g in GT]) if p.endswith('.tf')}

def token_hit(token, finding):
    if not token:
        return True
    pat = re.compile(r'(?<![A-Za-z0-9_])' + re.escape(token) + r'(?![A-Za-z0-9])')
    if pat.search(finding.get('resource', '') or ''):
        return True
    for p, lm in LINEMAP.items():
        if finding['file'].endswith(p) and finding.get('line') and lm.get(finding['line']) and pat.search(lm[finding['line']]):
            return True
    return False

# ---------------- Parsers ----------------
def load_json(p):
    try:
        with open(p, encoding='utf-8-sig') as f:
            return json.load(f)
    except Exception as e:
        print('  [!] o‘qilmadi:', p, e)
        return None

def parse_checkov(p):
    d = load_json(p)
    if d is None: return None
    d = d if isinstance(d, list) else [d]
    out = []
    for r in d:
        for fc in r.get('results', {}).get('failed_checks', []):
            lr = fc.get('file_line_range') or [None]
            out.append({'file': norm(fc.get('file_path')), 'resource': fc.get('resource', ''), 'line': lr[0],
                        'id': fc.get('check_id', ''), 'title': fc.get('check_name', ''), 'severity': fc.get('severity') or ''})
    return out

def parse_kics(p):
    d = load_json(p)
    if d is None: return None
    out = []
    for q in d.get('queries', []):
        for fl in q.get('files', []):
            out.append({'file': norm(fl.get('file_name')), 'resource': (fl.get('search_key') or '') + ' ' + (fl.get('resource_name') or ''),
                        'line': fl.get('line'), 'id': q.get('query_id', ''), 'title': q.get('query_name', ''), 'severity': q.get('severity', '')})
    return out

def parse_trivy_config(p):
    d = load_json(p)
    if d is None: return None
    out = []
    for r in d.get('Results', []) or []:
        for m in r.get('Misconfigurations', []) or []:
            if m.get('Status', 'FAIL') != 'FAIL': continue
            cm = m.get('CauseMetadata', {}) or {}
            out.append({'file': norm(r.get('Target')), 'resource': cm.get('Resource', ''), 'line': cm.get('StartLine'),
                        'id': m.get('ID', ''), 'title': m.get('Title', ''), 'severity': m.get('Severity', '')})
    return out

IAC_TOOLS = {
    'Checkov': ('checkov/results_json.json', parse_checkov),
    'KICS': ('kics/results.json', parse_kics),
    'Trivy (config)': ('trivy_config.json', parse_trivy_config),
}

def match(finding, g, side):
    f = g[side + '_file']; tok = g[side + '_token']
    if not finding['file'].endswith(norm(f)): return False
    text = (finding['id'] + ' ' + finding['title']).lower()
    if not re.search(g['regex'], text, re.I): return False
    if g['exclude'] and re.search(g['exclude'], text, re.I): return False
    return token_hit(tok, finding)

iac_summary = {}
iac_detail = []
for tool, (rel, parser) in IAC_TOOLS.items():
    runs = sorted(glob.glob(os.path.join(RES, 'iac', 'run*')))
    results = []
    for rd in runs:
        fs = parser(os.path.join(rd, rel)) if os.path.exists(os.path.join(rd, rel)) else None
        if fs is not None: results.append(fs)
    if not results:
        print(f'[i] {tool}: natija topilmadi'); continue
    fs = results[0]
    tp, fp = {}, {}
    used = set()
    for g in GT:
        hits = [i for i, x in enumerate(fs) if match(x, g, 'insecure')]
        fhits = [i for i, x in enumerate(fs) if match(x, g, 'secure')]
        tp[g['id']] = len(hits) > 0; fp[g['id']] = len(fhits) > 0
        used.update(hits)
        iac_detail.append({'tool': tool, 'id': g['id'], 'category': g['category'], 'detected': int(tp[g['id']]), 'fp_on_secure': int(fp[g['id']]),
                           'matched_rules': ' | '.join(sorted(set(fs[i]['id'] + ' ' + fs[i]['title'] for i in hits)))[:400],
                           'fp_rules': ' | '.join(sorted(set(fs[i]['id'] + ' ' + fs[i]['title'] for i in fhits)))[:400]})
    N = len(GT); TP = sum(tp.values()); FP = sum(fp.values())
    groups = {}
    for pre in ['TF', 'K8S', 'DF']:
        ids = [g['id'] for g in GT if g['id'].startswith(pre)]
        groups[pre] = {'n': len(ids), 'tp': sum(tp[i] for i in ids), 'fp': sum(fp[i] for i in ids)}
    insecure_n = sum(1 for x in fs if '/insecure/' in x['file']); secure_n = sum(1 for x in fs if '/secure/' in x['file'])
    prec = TP / (TP + FP) if TP + FP else 0
    rec = TP / N
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    iac_summary[tool] = {'gt': N, 'tp': TP, 'fn': N - TP, 'fp': FP, 'recall': rec, 'precision': prec, 'f1': f1,
                         'groups': groups, 'findings_total': len(fs), 'findings_insecure': insecure_n, 'findings_secure': secure_n,
                         'findings_unmatched_insecure': sum(1 for i, x in enumerate(fs) if '/insecure/' in x['file'] and i not in used),
                         'runs': len(results), 'run_counts': [len(r) for r in results], 'detected_ids': sorted(k for k, v in tp.items() if v),
                         'fp_ids': sorted(k for k, v in fp.items() if v)}

# IaC vositalari o'rtasidagi moslik
iac_overlap = {}
for a, b in itertools.combinations(iac_summary, 2):
    A, B = set(iac_summary[a]['detected_ids']), set(iac_summary[b]['detected_ids'])
    iac_overlap[f'{a} vs {b}'] = {'both': len(A & B), 'only_a': len(A - B), 'only_b': len(B - A),
                                  'jaccard': len(A & B) / len(A | B) if A | B else 0}
allsets = [set(v['detected_ids']) for v in iac_summary.values()]
missed_all = sorted(set(g['id'] for g in GT) - set().union(*allsets)) if allsets else []

# ---------------- Konteyner obrazlari ----------------
def cve_of(vid, related):
    if vid.upper().startswith('CVE-'): return vid.upper()
    for r in related or []:
        rid = r.get('id', '') if isinstance(r, dict) else str(r)
        if rid.upper().startswith('CVE-'): return rid.upper()
    return vid.upper()

def parse_trivy_img(p):
    d = load_json(p)
    if d is None: return None
    out = []
    for r in d.get('Results', []) or []:
        for v in r.get('Vulnerabilities', []) or []:
            out.append({'cve': cve_of(v.get('VulnerabilityID', ''), [{'id': x} for x in (v.get('VendorIDs') or [])]),
                        'pkg': v.get('PkgName', ''), 'ver': v.get('InstalledVersion', ''), 'sev': (v.get('Severity') or 'UNKNOWN').upper(),
                        'fix': bool(v.get('FixedVersion'))})
    return out

def parse_grype_img(p):
    d = load_json(p)
    if d is None: return None
    out = []
    for m in d.get('matches', []) or []:
        v = m.get('vulnerability', {}); a = m.get('artifact', {})
        out.append({'cve': cve_of(v.get('id', ''), m.get('relatedVulnerabilities')), 'pkg': a.get('name', ''), 'ver': a.get('version', ''),
                    'sev': (v.get('severity') or 'Unknown').upper(), 'fix': (v.get('fix', {}) or {}).get('state') == 'fixed'})
    return out

imgs = []
images_file = os.path.join(ROOT, 'images.txt')
if os.path.exists(images_file):
    imgs = [l.strip() for l in open(images_file, encoding='utf-8') if l.strip() and not l.startswith('#')]
img_rows = []
tot = {'Trivy': set(), 'Grype': set()}
for img in imgs:
    name = re.sub(r'[/:]', '_', img)
    row = {'image': img}
    sets = {}
    for tool, parser, pref in [('Trivy', parse_trivy_img, 'trivy'), ('Grype', parse_grype_img, 'grype')]:
        runs = sorted(glob.glob(os.path.join(RES, 'images', f'{pref}_{name}_run*.json')))
        res = [parser(p) for p in runs]
        res = [r for r in res if r is not None]
        if not res: continue
        v = res[0]
        sev = Counter(x['sev'] for x in v)
        cves = set(x['cve'] for x in v)
        sets[tool] = cves
        tot[tool] |= set(img + '|' + c for c in cves)
        row[f'{tool}_findings'] = len(v); row[f'{tool}_unique_cve'] = len(cves)
        row[f'{tool}_critical'] = sev.get('CRITICAL', 0); row[f'{tool}_high'] = sev.get('HIGH', 0)
        row[f'{tool}_medium'] = sev.get('MEDIUM', 0); row[f'{tool}_low'] = sev.get('LOW', 0) + sev.get('NEGLIGIBLE', 0)
        row[f'{tool}_fixable'] = sum(1 for x in v if x['fix'])
        row[f'{tool}_deterministic'] = int(all(len(r) == len(v) for r in res))
    if 'Trivy' in sets and 'Grype' in sets:
        A, B = sets['Trivy'], sets['Grype']
        row['common'] = len(A & B); row['only_trivy'] = len(A - B); row['only_grype'] = len(B - A)
        row['jaccard'] = round(len(A & B) / len(A | B), 3) if A | B else 1.0
        row['tversky_trivy_in_grype'] = round(len(A & B) / len(A), 3) if A else None
        row['tversky_grype_in_trivy'] = round(len(A & B) / len(B), 3) if B else None
    img_rows.append(row)

overall_img = {}
if tot['Trivy'] and tot['Grype']:
    A, B = tot['Trivy'], tot['Grype']
    overall_img = {'trivy_pairs': len(A), 'grype_pairs': len(B), 'common': len(A & B), 'jaccard': len(A & B) / len(A | B)}

# ---------------- Vaqt o'lchovlari ----------------
timing = defaultdict(list)
tfile = os.path.join(RES, 'timings.csv')
if os.path.exists(tfile):
    rows_t = list(csv.DictReader(open(tfile, encoding='utf-8-sig'), delimiter=';'))
    # Skript bir necha marta ishga tushirilgan bo'lsa, faqat oxirgi to'liq ishga tushirish olinadi
    starts = [i for i, r in enumerate(rows_t) if r['tool'].lstrip('\ufeff').strip() == 'checkov' and r['run'].strip() == '1']
    if starts: rows_t = rows_t[starts[-1]:]
    last = {}
    for r in rows_t: last[(r['tool'].lstrip('\ufeff').strip(), r['target'].strip(), r['run'].strip())] = r  # takrorlansa oxirgisi olinadi
    for r in last.values():
        try: timing[(r['tool'].lstrip('\ufeff').strip(), r['target'].strip())].append(float(r['seconds']))
        except: pass
timing_rows = [{'tool': k[0], 'target': k[1], 'n': len(v), 'mean_s': round(statistics.mean(v), 2),
                'sd_s': round(statistics.stdev(v), 2) if len(v) > 1 else 0} for k, v in sorted(timing.items())]

# ---------------- Bazalar sanasi ----------------
db_info = {}
tm = os.path.join(RES, 'trivy_db_metadata.json')
if os.path.exists(tm):
    d = load_json(tm) or {}
    db_info['trivy'] = {k: d.get(k) for k in ('Version', 'UpdatedAt', 'NextUpdate', 'DownloadedAt')}
gs = os.path.join(RES, 'grype_db_status.txt')
if os.path.exists(gs):
    db_info['grype'] = open(gs, encoding='utf-8-sig', errors='replace').read().strip()

# ---------------- Saqlash ----------------
json.dump({'iac_summary': iac_summary, 'iac_overlap': iac_overlap, 'missed_by_all': missed_all,
           'images': img_rows, 'images_overall': overall_img, 'timings': timing_rows, 'db_info': db_info},
          open(os.path.join(OUT, 'summary.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
def wcsv(name, rows):
    if not rows: return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with open(os.path.join(OUT, name), 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=keys, delimiter=';'); w.writeheader(); w.writerows(rows)
wcsv('iac_detail.csv', iac_detail); wcsv('images.csv', img_rows); wcsv('timings_summary.csv', timing_rows)

print('\n=== IaC ===')
for t, s in iac_summary.items():
    print(f"{t}: TP={s['tp']}/{s['gt']} recall={s['recall']:.3f} FP={s['fp']} precision={s['precision']:.3f} F1={s['f1']:.3f} "
          f"jami={s['findings_total']} (xavfsiz fayllarda {s['findings_secure']}) groups={s['groups']}")
print('Overlap:', iac_overlap); print('Hech biri topmagan:', missed_all)
print('\n=== Obrazlar ===')
for r in img_rows: print(r)
print('Umumiy:', overall_img)
print('\n=== Vaqt ===')
for r in timing_rows: print(r)
