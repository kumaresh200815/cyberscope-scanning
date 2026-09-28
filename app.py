from datetime import datetime
from html import escape
from pathlib import Path
from time import perf_counter
from flask import Flask, flash, redirect, render_template, request, send_from_directory, url_for
from database import init_db, list_scans, save_scan
from email_report import send_email_report
from pdf_report import generate_pdf_report
from recommendations import get_recommendations
from scanner.nmap_scanner import run_service_scan
from scanner.validator import is_allowed_target
from xml_report import generate_xml_report

app = Flask(__name__)
app.secret_key = "cyberscope-local-ui"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

def recommendations(services):
    tips=[]
    names={s["name"].lower() for s in services}
    tips.append("Review each exposed service and disable services that are not required." if services else "No open services were reported by the scan.")
    if "telnet" in names: tips.append("Replace Telnet with a secure remote-management method where possible.")
    if "ftp" in names: tips.append("Review FTP usage and prefer encrypted file-transfer methods.")
    if any(s["port"] in {22,3389} for s in services): tips.append("Restrict remote-administration services to trusted systems.")
    tips.append("Keep operating systems and network services patched and updated.")
    return tips

def create_html_report(target,result,duration,tips,filename):
    rows=[]
    for s in result["services"]:
        version=" ".join(v for v in [s.get("product",""),s.get("version",""),s.get("extrainfo","")] if v).strip() or "Not reported"
        rows.append(f"<tr><td>{escape(str(s['port']))}</td><td>{escape(str(s['protocol']))}</td><td>{escape(str(s['state']))}</td><td>{escape(str(s['name']))}</td><td>{escape(version)}</td></tr>")
    hosts=[]
    for h in result["hosts"]:
        hosts.append(f"<tr><td>{escape(str(h.get('address','')))}</td><td>{escape(str(h.get('hostname','')) or 'N/A')}</td><td>{escape(str(h.get('state','')))}</td><td>{escape(str(h.get('os','Not detected')))}</td></tr>")
    notes="".join(f"<li>{escape(t)}</li>" for t in tips)
    html=f'''<!doctype html><html><head><meta charset="utf-8"><title>CyberScope Report</title><style>body{{font-family:Arial;max-width:1050px;margin:40px auto;padding:0 20px}}table{{width:100%;border-collapse:collapse;margin:16px 0 28px}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#eef2f7}}</style></head><body><h1>CyberScope — Network Security Scan Report</h1><p><b>Target:</b> {escape(target)}</p><p><b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p><p><b>Duration:</b> {duration:.2f}s</p><p><b>Scan method:</b> {escape(result.get('scan_arguments',''))}</p><h2>Host & OS Information</h2><table><tr><th>Address</th><th>Hostname</th><th>State</th><th>Operating System</th></tr>{''.join(hosts) or '<tr><td colspan="4">No host information reported.</td></tr>'}</table><h2>Port, Protocol & Service Results</h2><table><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr>{''.join(rows) or '<tr><td colspan="5">No open services reported.</td></tr>'}</table><h2>Defensive Recommendations</h2><ul>{notes}</ul></body></html>'''
    (REPORT_DIR/filename).write_text(html,encoding="utf-8")

@app.route("/",methods=["GET","POST"])
def index():
    if request.method=="POST":
        target=request.form.get("target","").strip(); options=request.form.getlist("scan_options")
        if not is_allowed_target(target):
            flash("Enter localhost or a private/local target you are authorized to test."); return redirect(url_for("index"))
        started=perf_counter()
        try: result=run_service_scan(target,options)
        except Exception as e: flash(f"Scan failed: {e}"); return redirect(url_for("index"))
        duration=perf_counter()-started; tips=recommendations(result["services"])
        detailed=get_recommendations([s["port"] for s in result["services"]])
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file=f"cyberscope_{ts}.html"; pdf_file=f"cyberscope_{ts}.pdf"; xml_file=f"cyberscope_{ts}.xml"
        create_html_report(target,result,duration,tips,html_file)
        generate_pdf_report(str(REPORT_DIR/pdf_file),target,result["services"],detailed,result["hosts"])
        generate_xml_report(str(REPORT_DIR/xml_file),target,result["services"],result["hosts"])
        save_scan(target,datetime.now().isoformat(timespec="seconds"),duration,len(result["services"]),html_file)
        return render_template("results.html",target=target,result=result,duration=duration,tips=tips,scan_profile=", ".join(options) if options else "TCP",report_file=html_file,pdf_report_file=pdf_file,xml_report_file=xml_file)
    return render_template("index.html")

@app.post("/email-report")
def email_report():
    recipient=request.form.get("recipient","").strip(); report_file=request.form.get("report_file","").strip()
    if not recipient or not report_file: flash("Recipient and report are required."); return redirect(url_for("index"))
    report_path=REPORT_DIR/Path(report_file).name
    if not report_path.is_file(): flash("The requested report could not be found."); return redirect(url_for("index"))
    try: send_email_report(recipient,"CyberScope — Network Security Scan Report","Attached is the PDF report generated by CyberScope.",str(report_path))
    except Exception as e: flash(f"Email failed: {e}")
    else: flash(f"PDF report sent to {recipient}.")
    return redirect(url_for("index"))

@app.route("/history")
def history(): return render_template("history.html",scans=list_scans())
@app.route("/reports/<path:filename>")
def reports(filename): return send_from_directory(REPORT_DIR,filename,as_attachment=True)
if __name__=="__main__":
    init_db(); app.run(host="0.0.0.0",port=5000,debug=True)
