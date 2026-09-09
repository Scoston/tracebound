"""Self-contained, escaped HTML reports. No model-generated conclusions."""

import base64
import hashlib
import html
import json

STYLE = """
:root{color-scheme:dark;--bg:#0a1018;--panel:#111c29;--line:#24364b;--text:#edf3fa;--muted:#a8b9cb;--teal:#58e0c0;--red:#ff918a;--gold:#f6cb7a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1200px;margin:auto;padding:38px 42px 64px}a{color:var(--teal)}.bar{display:flex;justify-content:space-between;align-items:center;gap:16px;border-bottom:1px solid var(--line);padding-bottom:22px}.brand{font-size:22px;font-weight:800;letter-spacing:.12em}.brand b{color:var(--teal)}.eyebrow{color:var(--teal);font-size:12px;font-weight:700;letter-spacing:.13em;text-transform:uppercase}h1{font-size:clamp(32px,5vw,56px);line-height:1.08;letter-spacing:-.035em;margin:28px 0 18px;max-width:900px}h2{font-size:22px;margin:32px 0 14px}h3{font-size:20px;margin:0 0 8px}.lead{max-width:820px;color:var(--muted);font-size:18px}.muted,small{color:var(--muted)}.badge{display:inline-block;border:1px solid var(--line);border-radius:5px;padding:4px 9px;font-size:12px;white-space:nowrap}.bad{color:var(--red)}.good{color:var(--teal)}.unknown{color:var(--gold)}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:30px 0}.metric{background:var(--panel);border:1px solid var(--line);padding:19px;border-radius:10px}.metric strong{display:block;font-size:33px;line-height:1.2;margin-bottom:7px}.metric span{color:var(--muted);font-size:13px}.notice{border-left:3px solid var(--gold);padding:12px 18px;background:#1b2027;color:var(--muted)}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px;margin:18px 0}.card-top{display:flex;justify-content:space-between;align-items:flex-start;gap:20px}.columns{display:grid;grid-template-columns:1fr 1fr;gap:28px}.label{display:block;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:13px 14px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:9px}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}code{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:340px;overflow:auto;background:#080f17;padding:16px;border:1px solid var(--line);border-radius:6px}summary{cursor:pointer;color:var(--teal);padding:10px 0}select,button{font:inherit;color:var(--text);border:1px solid var(--line);background:var(--panel);padding:9px 12px;border-radius:6px}button{cursor:pointer}select:focus,button:focus,summary:focus{outline:2px solid var(--teal);outline-offset:3px}.toolbar{display:flex;align-items:center;gap:14px;margin:25px 0 8px}.path{display:grid;grid-template-columns:1fr 24px 1fr 24px 1fr;align-items:center;margin:18px 0;padding:18px;background:#0a1520;border-radius:8px;gap:8px}.path .node{border:1px solid var(--line);padding:12px;border-radius:6px;text-align:center}.path .arrow{color:var(--muted);text-align:center}.path small{display:block}footer{border-top:1px solid var(--line);margin-top:32px;padding-top:20px;font-size:12px;color:var(--muted)}[hidden]{display:none!important}@media(max-width:760px){main{padding:24px 16px}.metrics{grid-template-columns:repeat(2,1fr)}.columns{grid-template-columns:1fr}.card{padding:17px}.card-top,.bar{flex-wrap:wrap}.path{font-size:12px;padding:8px}.path .node{padding:8px 4px}th,td{padding:10px}.lead{font-size:16px}}@media print{:root{--bg:white;--panel:white;--text:#111;--muted:#444;--line:#bbb;--teal:#076a55;--red:#9b211c;--gold:#805400}body{background:white}.toolbar,button{display:none}.card{break-inside:avoid}.card[hidden]{display:block!important}pre{max-height:none}.notice,.path{background:#f4f6f8}main{padding:0}.metrics{margin:15px 0}}
"""
SCRIPT = """document.getElementById('scenario-filter')?.addEventListener('change',function(){document.querySelectorAll('[data-scenario]').forEach(card=>{card.hidden=this.value!=='all'&&card.dataset.scenario!==this.value;});});document.getElementById('print-report')?.addEventListener('click',()=>window.print());"""


def esc(value):
    return html.escape(str(value), quote=True)


def shell(title, body, created):
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; base-uri 'none'; form-action 'none'"><title>{esc(title)} | TraceBound</title><style>{STYLE}</style></head><body><main><header class="bar"><div class="brand">TRACE<b>BOUND</b></div><div><span class="badge">RESEARCH RELEASE · 0.1.0</span> <button id="print-report" type="button">Print report</button></div></header>{body}<footer>TraceBound · Dr. Stephen Coston · {esc(created)}<br>Verify the complete evidence bundle before relying on this presentation. Hashes and signatures establish bounded integrity properties; they do not establish source truth or complete containment.</footer></main><script>{SCRIPT}</script></body></html>'''


def render_lab(results):
    counts = results["summary"]
    metrics = [(counts["scenarios"], "Scenarios exercised"),
               (counts["initial_controls_failed"], "Surviving access paths observed"),
               (counts["remediated_paths_denied"], "Paths denied after remediation"),
               (counts["model_tokens"], "Model tokens consumed")]
    metric_html = "".join(f'<div class="metric"><strong>{value}</strong><span>{esc(label)}</span></div>' for value, label in metrics)
    rows, cards, options = [], [], []
    for number, finding in enumerate(results["findings"], 1):
        scenario = finding["scenario"]
        retest_class = "good" if finding["retest"]["observation"] == "denied" else "unknown"
        options.append(f'<option value="{esc(scenario)}">{esc(finding["title"])}</option>')
        rows.append(f'<tr><td><strong>{esc(finding["title"])}</strong></td><td class="bad">{esc(finding["initial"]["observation"])}</td><td class="good">{esc(finding["retest"]["observation"])}</td><td>{esc(finding["owner"])}</td></tr>')
        probes = "".join(f'<tr><td>{esc(p["phase"].replace("_", " "))}</td><td>{esc(p["principal"])}</td><td>{esc(p["observation"])}</td><td>{p["state_delta"]}</td><td>{p["round_trip_ms"]} ms</td></tr>' for p in (finding["baseline"], finding["initial"], finding["retest"]))
        cards.append(f'''<article class="card" data-scenario="{esc(scenario)}"><div class="card-top"><div><span class="eyebrow">Experiment {number:02d}</span><h3>{esc(finding["title"])}</h3></div><span class="badge {retest_class}">RETEST: {esc(finding["retest"]["observation"].upper())}</span></div><p class="muted">{esc(finding["exposure"])}</p><div class="path" aria-label="Observed authority path"><div class="node">{esc(finding["initial"]["principal"])}<small>Executing principal</small></div><span class="arrow">→</span><div class="node">Ticket update<small>{esc(finding["initial"]["observation"])} after initial boundary</small></div><span class="arrow">→</span><div class="node">{esc(finding["initial"]["ticket"])}<small>Resource state independently read</small></div></div><div class="columns"><p><span class="label">Remediation tested</span>{esc(finding["fix"])}</p><p><span class="label">Accountable owner</span>{esc(finding["owner"])}</p></div><div class="table-wrap"><table><thead><tr><th>Phase</th><th>Identity</th><th>Observation</th><th>State change</th><th>Round trip</th></tr></thead><tbody>{probes}</tbody></table></div><details><summary>Inspect evidence references and observations</summary><pre>{esc(json.dumps(finding, indent=2, sort_keys=True))}</pre></details></article>''')
    limits = "".join(f"<li>{esc(limit)}</li>" for limit in results["limits"])
    body = f'''<p class="eyebrow" style="margin-top:32px">Containment verification / Running local services</p><h1>Revocation issued.<br>What can still execute?</h1><p class="lead">Measured ticket operations across identity, session, delegation, queue, and approval boundaries. Every conclusion links to the recorded probe and resource evidence.</p><div class="metrics">{metric_html}</div><p class="notice">Scope: synthetic local lab. A denied retest verifies the observed path during this run. Production systems, other access paths, and later activity remain untested.</p><h2>Control outcomes</h2><div class="table-wrap"><table><thead><tr><th>Scenario</th><th>Initial boundary</th><th>After remediation</th><th>Owner</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div><div class="toolbar"><label for="scenario-filter">Inspect experiment</label><select id="scenario-filter"><option value="all">All scenarios</option>{''.join(options)}</select></div>{''.join(cards)}<h2>Evidence and exports</h2><p><a href="results.json">Structured results</a> · <a href="events.jsonl">Witness events</a> · <a href="authority.json">Authority graph</a> · <a href="chunk-index.json">Chunk byte index</a> · <a href="afr-events.jsonl">Forensic Readiness projection</a></p><p class="muted">The graph contains declared lab grants and observed operations. It is not a discovery scan of enterprise permissions.</p><h2>Interpretation limits</h2><ul>{limits}</ul><p class="muted">Run ID: <code>{esc(results["run_id"])}</code></p>'''
    return shell("Containment evidence report", body, results["created_at"])


def markdown_lab(results):
    counts = results["summary"]
    lines = ["# TraceBound containment report", "", "Mode: running local services with synthetic principals and tickets.", "",
        f"{counts['scenarios']} scenarios; {counts['probes']} probes; {counts['initial_controls_failed']} surviving paths observed; {counts['remediated_paths_denied']} paths denied after remediation.", "",
        "| Scenario | Initial observation | Remediated observation | Owner |", "|---|---|---|---|"]
    for f in results["findings"]:
        lines.append(f"| {f['title']} | {f['initial']['observation']} | {f['retest']['observation']} | {f['owner']} |")
    lines += ["", "## Findings", ""]
    for f in results["findings"]:
        lines += [f"### {f['title']}", "", f["exposure"], "", "Remediation: " + f["fix"], "",
            "Initial resource receipt: `" + str(f["initial"]["receipt_chunk_id"]) + "`",
            "", "Retest resource receipt: `" + str(f["retest"]["receipt_chunk_id"]) + "`", ""]
    lines += ["## Limits", ""] + ["- " + item for item in results["limits"]]
    lines += ["", "Timing measures controller observation intervals around explicit interventions. It is not a natural token-expiration benchmark.", "",
        "Verify the manifest and recorded-result replay. Pin the manifest digest or signing key independently.", ""]
    return "\n".join(lines)


def render_entra(results):
    summary = results["summary"]
    body = f'''<p class="eyebrow" style="margin-top:32px">Microsoft Entra / Operator-controlled observation</p><h1>Access observed after<br>the containment marker.</h1><p class="lead">This report records requests to the fixed Microsoft Graph /me canary using the same pre-existing delegated access token. Revocation is performed independently by the operator.</p><div class="metrics"><div class="metric"><strong>{summary["post_marker_allowed"]}</strong><span>Post-marker successes</span></div><div class="metric"><strong>{summary["post_marker_denied"]}</strong><span>Post-marker denials</span></div><div class="metric"><strong>{summary["post_marker_unknown"]}</strong><span>Unknown observations</span></div><div class="metric"><strong>0</strong><span>Model tokens</span></div></div><p class="notice">The local marker records the operator's assertion. This adapter does not establish when Microsoft applied revocation or what caused a later denial. It does not test refresh tokens, application sessions, child identities, or other resources.</p><h2>Observation summary</h2><pre>{esc(json.dumps(summary, indent=2, sort_keys=True))}</pre><p><a href="observations.jsonl">Observation ledger</a> · <a href="entra-plan.json">Approved test plan</a> · <a href="results.json">Structured results</a></p>'''
    return shell("Entra access observations", body, results["created_at"])
