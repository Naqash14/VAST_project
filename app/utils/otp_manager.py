from app.models import OTP, User, db
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class OTPManager:
    
    @staticmethod
    def create_otp(email):
        try:
            OTP.query.filter_by(email=email, is_used=False).delete()
            
            otp = OTP(email=email)
            db.session.add(otp)
            db.session.commit()
            
            logger.info(f"✅ OTP created for {email}: {otp.otp_code}")
            return otp.otp_code
            
        except Exception as e:
            logger.error(f"OTP creation failed: {e}")
            db.session.rollback()
            return None
    
    @staticmethod
    def verify_otp(email, otp_code):
        try:
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                is_used=False
            ).first()
            
            if not otp:
                return False, "Invalid OTP"
            
            if otp.attempts >= 3:
                return False, "Too many attempts"
            
            if datetime.utcnow() > otp.expires_at:
                return False, "OTP expired"
            
            otp.is_used = True
            db.session.commit()
            
            logger.info(f"✅ OTP verified for {email}")
            return True, "OTP verified"
            
        except Exception as e:
            logger.error(f"OTP verification error: {e}")
            return False, "Verification failed"
    
    @staticmethod
    def increment_attempts(email, otp_code):
        try:
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                is_used=False
            ).first()
            
            if otp:
                otp.attempts += 1
                db.session.commit()
                
                if otp.attempts >= 3:
                    otp.is_used = True
                    db.session.commit()
                    return True, "OTP locked"
            
            return False, "Attempt recorded"
            
        except Exception as e:
            logger.error(f"Attempt error: {e}")
            return False, "Error"
