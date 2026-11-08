"""Recalculate STI #5983 checklist evidence without rerunning experiments.
Run: python tools/check_sti_5983.py
Uses only the standard library; frozen artifacts are read-only.
"""
import ast
import csv
import json
import math
from fractions import Fraction
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
def rows(name):
    with (ROOT / 'results' / name).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))
def close(a, b):
    assert abs(float(a)-float(b)) < 1e-9, (a, b)
def count(row, name):
    return int(float(row.get(name) or row[name+'_count']))

def main():
    splits = {}
    for row in rows('closed_set_split_counts.csv'):
        splits[row['split']] = splits.get(row['split'], 0) + int(row['row_count'])
    assert splits == {'train': 428477, 'calibration': 91819, 'test': 91819}
    audit = dict(line.split(': ', 1) for line in (ROOT/'results/duplicate_audit.txt').read_text().splitlines())
    sampled = int(audit['TOTAL RESEARCH POOL ROWS'])
    excluded = int(audit['ROWS IN LABEL-CONFLICT GROUPS'])
    assert sampled == 637892 and excluded == 25777
    assert sampled - excluded == sum(splits.values()) == 612115
    assert sum(int(r['record_count']) for r in rows('family_counts.csv')) == 46776700
    assert sum(int(r['final_valid_count']) for r in rows('research_pool_family_counts.csv')) == sampled
    key = json.loads((ROOT/'paper_assets/data/key_numbers.json').read_text())
    assert key['data']['modeling_pool_rows'] == 612115
    with (ROOT/'paper_assets/tables/table01_dataset_summary.csv').open() as f:
        table = {r['Item']: int(r['Value']) for r in csv.DictReader(f)}
    assert table['Modeling pool'] == 612115 and table['Conflicting rows excluded'] == excluded

    outer = rows('ecocon_nos_outer_results.csv')
    metrics = {}
    for r in outer:
        ak, au = count(r, 'accepted_known'), count(r, 'accepted_unknown')
        wrong = count(r, 'wrong_known_accepted')
        nk, nu = int(r['known_count']), int(r['unknown_count'])
        assert ak+au > 0
        vals = {'UADR': Fraction(count(r,'unknown_rejected'), nu),
                'overall_selective_risk': Fraction(wrong+au, ak+au),
                'known_rejection_rate': Fraction(count(r,'known_rejected'), nk),
                'coverage': Fraction(ak+au,nk+nu),
                'review_rate': 1-Fraction(ak+au,nk+nu)}
        for k,v in vals.items(): close(v,r[k])
        metrics[r['held_out_family'], r['method']] = vals
    for r in rows('ecocon_nos_macro_summary.csv'):
        selected = [v for (f,m),v in metrics.items() if m == r['method']]
        assert len(selected) == 7
        for k in selected[0]: close(mean(v[k] for v in selected), r[k])
    families = sorted({f for f,m in metrics})
    gains = {f: metrics[f,'EcoConNOS']['UADR']-metrics[f,'EcoConMD']['UADR'] for f in families}
    assert max(gains,key=gains.get) == 'Recon'
    for r in rows('ecocon_nos_family_comparison.csv'):
        for m in ['MSP','Entropy','EcoConMD','EcoConNOS']:
            close(metrics[r['held_out_family'],m]['UADR'],r[m])
    print('Counts, all outer metrics, macro means and family results: PASS')
    print('NOS minus MD UADR (percentage points):', {f:float(v*100) for f,v in gains.items()})
    print('MSP/Entropy macro UADR:', {m:float(mean(metrics[f,m]['UADR'] for f in families)) for m in ['MSP','Entropy']})

    # Reproduce the exact two-sided signed-rank distribution, not a new test.
    for r in rows('ecocon_nos_statistics.csv'):
        baseline = r['comparison'].split(' vs ')[1]
        d = [metrics[f,'EcoConNOS'][r['outcome']]-metrics[f,baseline][r['outcome']] for f in families]
        assert all(d) and len(set(map(abs,d))) == 7  # no zeros or tied magnitudes
        ranks = {v:i+1 for i,v in enumerate(sorted(map(abs,d)))}
        positive = sum(ranks[abs(v)] for v in d if v > 0)
        statistic = min(positive,28-positive)
        sums = [sum(i+1 for i in range(7) if mask & (1<<i)) for mask in range(128)]
        p = min(1,2*sum(s <= statistic for s in sums)/128)
        close(statistic,r['wilcoxon_statistic']); close(p,r['p_value'])
        close(mean(d),r['mean_paired_difference'])
        close(sorted(d)[3],r['median_paired_difference'])
        wins = sum(v > 0 if r['outcome']=='UADR' else v < 0 for v in d)
        assert wins == int(r['wins']) and 7-wins == int(r['losses']) and int(r['ties']) == 0
        print(r['comparison'], r['outcome'], 'W=',statistic,'two-sided exact p=',p)
    assert len(rows('ecocon_nos_statistics.csv')) == 6
    fresh = rows('ecocon_nos_fresh_confirmation.csv')
    prior = {r['held_out_family']:r for r in rows('step8_5_fresh_confirmation.csv')}
    assert len(fresh)==5 and sum(int(r['fresh_rows']) for r in fresh)==25000
    for r in fresh:
        for m in ['MSP','Entropy','EcoConMD']: close(r[m+'_UADR'],prior[r['held_out_family']][m+'_UADR'])
        for m in ['MSP','Entropy','EcoConMD','EcoConNOS']:
            close(float(r[m+'_UADR'])*5000,round(float(r[m+'_UADR'])*5000))
    print('Fresh CSV totals, integer detections and prior baseline consistency: PASS (Parquet overlap not rechecked)')

    source = (ROOT/'src/08_6_ecocon_nested_open_set.py').read_text()
    tree = ast.parse(source)
    helper = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='selective_risk')
    ns = {}
    exec(compile(ast.Module(body=[helper],type_ignores=[]),'<selective_risk>','exec'),ns)
    risk = ns['selective_risk']
    assert math.isnan(risk(0,0)) and risk(0,3)==0 and risk(3,3)==1
    assert risk(2,10)==0.2 and risk(2,5)==0.4  # rejecting correct known rows raises risk
    for r in outer:
        ak,au=count(r,'accepted_known'),count(r,'accepted_unknown')
        close(risk(count(r,'wrong_known_accepted')+au,ak+au),r['overall_selective_risk'])
    assert "'overall_selective_risk':selective_risk(wrong,acc)" in source
    generator=(ROOT/'src/09_build_publication_assets.py').read_text()
    assert 'columns=[]' not in generator
    assert "columns=['feature_hash']" in generator
    assert 'range(2): h.write(results_extra)' not in generator
    for p in [* (ROOT/'src').glob('*.py'), * (ROOT/'tools').glob('*.py')]:
        ast.parse(p.read_text(encoding='utf-8-sig'),filename=str(p))
    print('Empty-acceptance regression, unchanged saved risks, generator guards and Python syntax: PASS')

if __name__ == '__main__':
    main()
