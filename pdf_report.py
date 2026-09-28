from html import escape
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
def generate_pdf_report(filename,target,scan_results,recommendations=None,hosts=None):
    doc=SimpleDocTemplate(filename,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36); styles=getSampleStyleSheet(); story=[Paragraph("CyberScope — Network Scan Report",styles["Title"]),Spacer(1,.15*inch),Paragraph(f"<b>Target:</b> {escape(str(target))}",styles["Normal"]),Spacer(1,.12*inch)]
    for h in hosts or []: story.append(Paragraph(f"<b>Host:</b> {escape(str(h.get('address','Unknown')))} | <b>State:</b> {escape(str(h.get('state','unknown')))} | <b>OS:</b> {escape(str(h.get('os','Not detected')))}",styles["Normal"]))
    story += [Spacer(1,.15*inch),Paragraph("Port & Service Results",styles["Heading2"]),Spacer(1,.08*inch)]
    data=[["Port","Protocol","State","Service","Version"]]
    for r in scan_results or []: data.append([str(r.get("port","Unknown")),str(r.get("protocol","TCP")),str(r.get("state","unknown")),str(r.get("name",r.get("service","Unknown")))," ".join(v for v in [r.get("product",""),r.get("version",""),r.get("extrainfo","")] if v).strip() or "Not reported"])
    if len(data)==1:data.append(["-","-","-","No open services reported","-"])
    table=Table(data,repeatRows=1,colWidths=[45,55,55,105,210]); table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e9eef5")),("GRID",(0,0),(-1,-1),.5,colors.grey),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [table,Spacer(1,.2*inch),Paragraph("Defensive Recommendations",styles["Heading2"])]
    for rec in recommendations or []: story += [Paragraph(f"• {escape(rec.get('message','') if isinstance(rec,dict) else str(rec))}",styles["Normal"]),Spacer(1,.06*inch)]
    doc.build(story); return filename
