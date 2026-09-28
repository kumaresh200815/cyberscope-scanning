import xml.etree.ElementTree as ET
def generate_xml_report(filename,target,scan_results,hosts=None):
    root=ET.Element("cyberscope_report"); ET.SubElement(root,"target").text=str(target); he=ET.SubElement(root,"hosts")
    for h in hosts or []:
        x=ET.SubElement(he,"host"); ET.SubElement(x,"address").text=str(h.get("address","")); ET.SubElement(x,"hostname").text=str(h.get("hostname","")); ET.SubElement(x,"state").text=str(h.get("state","")); ET.SubElement(x,"operating_system").text=str(h.get("os","Not detected"))
    re=ET.SubElement(root,"scan_results")
    for r in scan_results or []:
        x=ET.SubElement(re,"service")
        for k,n in [("port","port"),("protocol","protocol"),("state","state"),("name","service_name"),("product","product"),("version","version"),("extrainfo","extra_info")]: ET.SubElement(x,n).text=str(r.get(k,""))
    tree=ET.ElementTree(root)
    try: ET.indent(tree,space="  ")
    except AttributeError: pass
    tree.write(filename,encoding="utf-8",xml_declaration=True); return filename
