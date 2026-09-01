import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()


def send_otp_email(to_email: str, otp: str):

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM")

    if not all([
        smtp_host,
        smtp_username,
        smtp_password,
        smtp_from
    ]):
        raise RuntimeError(
            "SMTP configuration is incomplete"
        )

    message = EmailMessage()

    message["Subject"] = "RDRS Password Reset OTP"
    message["From"] = smtp_from
    message["To"] = to_email

    message.set_content(
        f"""
RDRS Security System

Your password reset OTP is:

{otp}

This OTP is valid for 10 minutes.

If you did not request a password reset,
please ignore this email.

Regards,
RDRS Security Team
"""
    )

    with smtplib.SMTP(
        smtp_host,
        smtp_port,
        timeout=30
    ) as server:

        server.starttls()

        server.login(
            smtp_username,
            smtp_password
        )

        server.send_message(message)

    return True


print("✅ Email service loaded")
