from app import create_app
from app.utils.email_service import send_otp_email

app = create_app()
with app.app_context():
    email = input("Enter your email: ")
    otp = "123456"
    print(f"Sending to {email}...")
    result = send_otp_email(email, otp)
    if result:
        print("✅ SUCCESS! Check your inbox!")
    else:
        print("❌ FAILED! Check settings")
