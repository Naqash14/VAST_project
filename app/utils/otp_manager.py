from app.models import OTP, db
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class OTPManager:
    """Handle OTP operations"""
    
    @staticmethod
    def create_otp(email):
        """
        Create new OTP for email
        Returns: otp_code or None
        """
        try:
            # Delete old unused OTPs
            OTP.query.filter_by(email=email, is_used=False).delete()
            db.session.commit()
            
            # Create new OTP
            otp = OTP(email=email)
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
        """
        Verify OTP code
        Returns: (success, message)
        """
        try:
            print(f"🔍 Verifying OTP - Email: {email}, Code: {otp_code}")
            
            # Find OTP
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                is_used=False
            ).first()
            
            if not otp:
                print(f"❌ OTP not found in database")
                return False, "Invalid OTP code"
            
            print(f"📊 OTP found - Created: {otp.created_at}, Expires: {otp.expires_at}, Attempts: {otp.attempts}")
            
            # Check attempts
            if otp.attempts >= 3:
                print(f"❌ Too many attempts: {otp.attempts}")
                return False, "Too many failed attempts"
            
            # Check expiry
            now = datetime.utcnow()
            if now > otp.expires_at:
                print(f"❌ OTP expired - Now: {now}, Expires: {otp.expires_at}")
                return False, "OTP has expired"
            
            # Mark as used
            otp.is_used = True
            db.session.commit()
            
            print(f"✅ OTP verified successfully")
            return True, "OTP verified successfully"
            
        except Exception as e:
            logger.error(f"❌ OTP verification error: {e}")
            db.session.rollback()
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
                print(f"⚠️ Incremented attempts for {email}: {otp.attempts}")
                
                if otp.attempts >= 3:
                    otp.is_used = True
                    db.session.commit()
                    return True, "OTP locked - too many attempts"
            
            return False, "Attempt recorded"
            
        except Exception as e:
            logger.error(f"❌ Attempt increment error: {e}")
            return False, "Error"
