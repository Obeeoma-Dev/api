"""
AI Service for Public Receptionist Chat
Provides conversational responses for registration, features, and platform guidance
"""

def get_receptionist_response(message: str, session_id: str) -> str:
    """
    Generate AI response for receptionist chat.
    Focuses on registration guidance, platform features, and user support.
    """
    message_lower = message.lower()
    
    # Platform registration guidance
    if any(word in message_lower for word in ['register', 'signup', 'create account', 'join', 'start']):
        return """Welcome!  Let me guide you through getting started with Obeeoma:

**Registration Steps:**
1. Click "Sign Up" on our landing page
2. Choose your role: Employee or Employer
3. Fill in your basic information
4. Verify your email address
5. Complete your profile setup

**Mobile App:** Download our app from App Store or Google Play for the best experience! 📱

Need help with any specific step? I'm here to assist!"""
    
    # Mobile app questions
    elif any(word in message_lower for word in ['mobile', 'app', 'phone', 'download']):
        return """**Obeeoma Mobile App** 

**Features:**
- Mental health assessments on the go
- AI-powered wellness conversations  
- Crisis support hotline (24/7)
- Track your mood and progress
- Access company resources
- Push notifications for appointments

**Download:**
- App Store: Search "Obeeoma"
- Google Play: Search "Obeeoma"
- Direct links on our website

The app syncs seamlessly with your web account!"""
    
    # Platform features
    elif any(word in message_lower for word in ['features', 'what can', 'how to', 'help', 'services']):
        return """**Obeeoma Platform Features** 

**For Employees:**
- Mental health assessments
- AI wellness conversations  
- Crisis support & counseling
- Personal wellness tracking
- Mobile app access
- Company resources

**For Employers:**
- Employee wellness analytics
- Organization management
- Wellness programs
- Resource library
- Engagement tracking

**Getting Started:**
1. Register your account
2. Complete your profile
3. Take your first assessment
4. Explore resources
5. Download mobile app

What would you like to explore first?"""
    
    # Payment/billing
    elif any(word in message_lower for word in ['cost', 'price', 'payment', 'billing', 'money']):
        return """**Obeeoma Pricing** 

**Free Tier:**
- Basic assessments
- Limited AI conversations
- Community resources

**Premium Plans:**
- Individual: $9.99/month
- Team: $49.99/month (up to 10 users)
- Enterprise: Custom pricing

**What's Included:**
- Unlimited AI conversations
- Advanced analytics
- Priority support
- Custom wellness programs
- Mobile app full access

**Billing:**
- Monthly or annual options
- Cancel anytime
- Enterprise invoicing available

Want to see a detailed comparison?"""
    
    # Account access and login
    elif any(word in message_lower for word in ['login', 'access', 'account', 'sign in', 'how do i']):
        return """**Account Access** 

**To Login:**
1. Go to our website or open the mobile app
2. Click "Sign In" 
3. Enter your email and password
4. Click "Login"

**Forgot Password?**
- Click "Forgot Password" on login page
- Enter your email address
- Check your email for reset link
- Create new password

**First Time Login?**
- Use the password you created during registration
- Check your email for login credentials
- Mobile app: Use same email/password as web

**Having Trouble?**
- Verify you're using the correct email
- Check that Caps Lock is off
- Try resetting your password
- Contact support if issues persist

Need help with any specific login step?"""
    
    # Technical support
    elif any(word in message_lower for word in ['problem', 'issue', 'error', 'bug', 'support']):
        return """**Technical Support** 

**Common Solutions:**
- Clear browser cache and cookies
- Update to latest browser version
- Check internet connection
- Try the mobile app

**Get Help:**
- Email: support@obeeoma.com
- Live chat (business hours)
- App: Help section
- Phone: 1-800-OBEOMA

**Response Times:**
- Email: Within 24 hours
- Live chat: Immediate (during hours)
- Premium: Priority support

What specific issue are you experiencing?"""
    
    # Contact information
    elif any(word in message_lower for word in ['contact', 'email', 'phone', 'reach']):
        return """**Contact Obeeoma** 

**Get in Touch:**
- Email: info@obeeoma.com
- Live Chat: Available on website
- Phone: 1-800-OBEOMA
- Website: www.obeeoma.com

**Business Hours:**
- Monday-Friday: 9AM-6PM (GMT)
- Weekend: Limited support
- Emergency: 24/7 crisis line

**Response Times:**
- General inquiries: Within 24 hours
- Technical support: 2-4 hours
- Emergency: Immediate

How can I help you get started today?"""
    
    # Greeting responses
    elif any(greeting in message_lower for greeting in ['hello', 'hi', 'hey', 'good morning', 'good afternoon', 'greetings']):
        return """Hello! Welcome to Obeeoma!

I'm your AI receptionist, here to help you with:
- Platform registration and setup
- Mobile app features and downloads  
- Platform features and capabilities
- Pricing and billing questions
- Technical support guidance
- Organization management
- Mental health resources

**Quick Start:**
- New to Obeeoma? Ask about "registration"
- Want mobile access? Ask about "mobile app"
- Need features overview? Ask about "features"

What would you like to know about Obeeoma today?"""
    
    # Default conversational response
    else:
        return """Hello! I'm your Obeeoma receptionist assistant.

I'm here to help you with:
- Platform registration and setup
- Mobile app features and downloads  
- Platform features and capabilities
- Pricing and billing questions
- Technical support guidance
- Organization management
- Mental health resources

**Quick Start:**
- New to Obeeoma? Ask about "registration"
- Want mobile access? Ask about "mobile app"
- Need features overview? Ask about "features"

What would you like to know about Obeeoma today? I'll guide you step by step! """
