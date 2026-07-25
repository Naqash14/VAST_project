from app.models import OTP, User, db
from datetime import datetime, timedelta
import secrets
import logging

logger = logging.getLogger(__name__)

class OTPManager:
    """OTP management with Railway compatibility"""
    
    @staticmethod
    def create_otp(email, user_id=None):
        """Create new OTP and log it"""
        try:
            # Delete old unused OTPs
            OTP.query.filter_by(email=email, is_used=False).delete()
            db.session.commit()
            
            # Create new OTP
            otp = OTP(email=email, user_id=user_id)
            db.session.add(otp)
            db.session.commit()
            
            logger.info(f"✅ OTP created for {email}: {otp.otp_code}")
            return otp.otp_code
            
        except Exception as e:
            logger.error(f"❌ OTP creation failed: {e}")
            db.session.rollback()
            return None
    
    @staticmethod
    def verify_otp(email, otp_code):
        """Verify OTP code"""
        try:
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                is_used=False
            ).first()
            
            if not otp:
                logger.warning(f"Invalid OTP attempt for {email}")
                return False, "Invalid OTP code"
            
            if otp.attempts >= 3:
                return False, "Too many failed attempts"
            
            if datetime.utcnow() > otp.expires_at:
                return False, "OTP has expired"
            
            otp.is_used = True
            db.session.commit()
            
            logger.info(f"✅ OTP verified for {email}")
            return True, "OTP verified successfully"
            
        except Exception as e:
            logger.error(f"OTP verification error: {e}")
            return False, "Verification failed"
    
    @staticmethod
    def increment_attempts(email, otp_code):
        """Track failed attempts"""
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
                    return True, "OTP locked - too many attempts"
            
            return False, "Attempt recorded"
            
        except Exception as e:
            logger.error(f"Attempt increment error: {e}")
            return False, "Error"
