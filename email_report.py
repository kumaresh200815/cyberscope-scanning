import os,smtplib
from email.message import EmailMessage
def send_email_report(recipient,subject,body,attachment_path=None,sender=None,password=None):
    sender=sender or os.getenv("CYBERSCOPE_EMAIL"); password=password or os.getenv("CYBERSCOPE_EMAIL_PASSWORD"); smtp_server=os.getenv("CYBERSCOPE_SMTP_SERVER","smtp.gmail.com"); smtp_port=int(os.getenv("CYBERSCOPE_SMTP_PORT","587"))
    if not sender or not password: raise ValueError("Email credentials are not configured. Set CYBERSCOPE_EMAIL and CYBERSCOPE_EMAIL_PASSWORD.")
    message=EmailMessage(); message["From"]=sender; message["To"]=recipient; message["Subject"]=subject; message.set_content(body)
    if attachment_path and os.path.isfile(attachment_path):
        with open(attachment_path,"rb") as f: message.add_attachment(f.read(),maintype="application",subtype="octet-stream",filename=os.path.basename(attachment_path))
    with smtplib.SMTP(smtp_server,smtp_port) as server: server.starttls(); server.login(sender,password); server.send_message(message)
    return True
