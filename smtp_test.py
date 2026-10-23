import smtplib, ssl, getpass

user = "hanzalahjamalbscs@gmail.com"
pw = getpass.getpass("App password: ").replace(" ", "")

print("=== Port 587 (STARTTLS) ===")
try:
    s = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
    s.set_debuglevel(1)
    s.starttls(context=ssl.create_default_context())
    s.login(user, pw)
    print("LOGIN OK on 587")
    s.quit()
except Exception as e:
    print("587 failed:", repr(e))

print("=== Port 465 (SSL) ===")
try:
    s = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20, context=ssl.create_default_context())
    s.set_debuglevel(1)
    s.login(user, pw)
    print("LOGIN OK on 465")
    s.quit()
except Exception as e:
    print("465 failed:", repr(e))