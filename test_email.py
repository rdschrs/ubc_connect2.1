import os
import asyncio
from dotenv import load_dotenv
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

# Load the secret password
load_dotenv()

print("--- EMAIL DIAGNOSTIC TOOL ---")
print(f"1. Username: {os.getenv('MAIL_USERNAME')}")
# We print only the first 2 chars of the password for safety
pwd = os.getenv('MAIL_PASSWORD')
print(f"2. Password Loaded: {'Yes' if pwd else 'NO'} ({pwd[:2]}***)" if pwd else "2. Password Loaded: NO")

# Configuration
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

async def simple_send():
    print("3. Attempting to connect to Gmail...")
    
    # REPLACE THIS with your actual personal email to test
    RECIPIENT = os.getenv("MAIL_USERNAME") 
    
    message = MessageSchema(
        subject="Test Email from Python",
        recipients=[RECIPIENT],
        body="If you see this, the connection is WORKING!",
        subtype=MessageType.plain
    )

    fm = FastMail(conf)
    try:
        await fm.send_message(message)
        print("✅ SUCCESS! Email sent. Check your inbox.")
    except Exception as e:
        print(f"❌ FAILED: {e}")

if __name__ == "__main__":
    asyncio.run(simple_send())