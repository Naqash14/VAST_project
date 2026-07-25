from app.models import OTP, db
from datetime import datetime
import random
import logging

logger = logging.getLogger(__name__)

class OTPManager:
    """Handle OTP operations"""
    
    @staticmethod
    def create_otp(email):
        """Create new OTP for email"""
        try:
            # Delete old unused OTPs
            OTP.query.filter_by(email=email, is_used=False).delete()
            db.session.commit()
            
            # Create new OTP
            otp = OTP(email=email)
            db.session.add(otp)
            db.session.commit()
            
            logger.info(f"OTP created for {email}: {otp.otp_code}")
            return otp.otp_code
            
        except Exception as e:
            logger.error(f"OTP creation failed: {e}")
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
                return False, "Invalid OTP code"
            
            if otp.attempts >= 3:
                return False, "Too many failed attempts"
            
            if datetime.utcnow() > otp.expires_at:
                return False, "OTP has expired"
            
            otp.is_used = True
            db.session.commit()
            
            return True, "OTP verified successfully"
            
        except Exception as e:
            logger.error(f"OTP verification error: {e}")
            return False, "Verification failed"
