import nmap
ALLOWED_OPTIONS={"tcp","udp","syn","version","os","aggressive"}
def _extract_os(host_data):
    matches=host_data.get("osmatch",[]) or []
    if not matches:return "Not detected"
    best=matches[0]; name=best.get("name","Unknown OS"); accuracy=best.get("accuracy")
    return f"{name} ({accuracy}% match)" if accuracy else name
def build_arguments(options):
    selected=set(options or []) & ALLOWED_OPTIONS; args=[]
    if "syn" in selected: args.append("-sS")
    elif "tcp" in selected or not ({"tcp","udp"}&selected): args.append("-sT")
    if "udp" in selected: args.append("-sU")
    if "version" in selected: args.append("-sV")
    if "os" in selected: args.append("-O")
    if "aggressive" in selected: args.append("-A")
    args += ["-T3","--top-ports","1000"]; return " ".join(args)
def run_service_scan(target,options=None):
    arguments=build_arguments(options); scanner=nmap.PortScanner()
    try: scanner.scan(hosts=target,arguments=arguments); note=""
    except nmap.PortScannerError as error:
        fallback="-sT -sV --version-light -T3 --top-ports 1000"; scanner=nmap.PortScanner(); scanner.scan(hosts=target,arguments=fallback); arguments=fallback; note=f"Requested scan could not run with current privileges; fallback TCP service scan was used. ({error})"
    result={"hosts":[],"services":[],"scan_arguments":arguments,"scan_note":note}
    for host in scanner.all_hosts():
        hd=scanner[host]; result["hosts"].append({"address":host,"hostname":hd.hostname(),"state":hd.state(),"os":_extract_os(hd)})
        for protocol in hd.all_protocols():
            for port in sorted(hd[protocol].keys()):
                item=hd[protocol][port]; result["services"].append({"host":host,"protocol":protocol.upper(),"port":port,"state":item.get("state","unknown"),"name":item.get("name","unknown"),"product":item.get("product",""),"version":item.get("version",""),"extrainfo":item.get("extrainfo","")})
    return result
