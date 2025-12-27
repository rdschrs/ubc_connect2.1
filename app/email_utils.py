import os
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr
from dotenv import load_dotenv
import random
import string

# Load environment variables
load_dotenv()

# 1. Production Configuration
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
    # NOTICE: 'SUPPRESS_SEND' is removed! It will now really send.
)

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

async def send_verification_email(email: EmailStr, code: str):
    message = MessageSchema(
        subject="Your UBC Connect Verification Code",
        recipients=[email],
        body=f"Welcome to UBC Connect! Your verification code is: {code}",
        subtype=MessageType.plain
    )
    
    fm = FastMail(conf)
    await fm.send_message(message)
    print(f"✅ Email sent successfully to {email}")