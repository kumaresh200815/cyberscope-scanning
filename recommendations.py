def get_recommendations(ports):
    tips=[]
    for port in sorted(set(ports or [])):
        if port==21: tips.append({"message":"Review FTP exposure and prefer encrypted file transfer."})
        elif port==22: tips.append({"message":"Restrict SSH access to trusted hosts and use strong authentication."})
        elif port==23: tips.append({"message":"Avoid Telnet where possible; replace it with encrypted remote administration."})
        elif port==3389: tips.append({"message":"Restrict RDP to trusted networks and require strong authentication."})
    if not tips: tips.append({"message":"Review open services and keep exposed software patched."})
    return tips
