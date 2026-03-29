"""
AI Service for Public Receptionist Chat
Provides simple responses for landing page visitors
"""

def get_receptionist_response(message: str, session_id: str) -> str:
    """
    Generate AI response for receptionist chat.
    Simple rule-based responses for now.
    """
    message_lower = message.lower()
    
    # Greeting responses
    if any(greeting in message_lower for greeting in ['hello', 'hi', 'hey', 'good morning', 'good afternoon']):
        return "Hello! Welcome to Obeeoma! 👋 I'm Sana, your AI receptionist. I'm here to tell you about our mental health platform and answer any questions you might have about our services."
    
    # Service information
    elif 'service' in message_lower or 'what do you do' in message_lower or 'what is obeeoma' in message_lower:
        return "Obeeoma is a comprehensive mental health platform designed for Africa's workforce. We provide AI-powered mental health support, wellness assessments, crisis intervention, employee assistance programs, and organizational analytics to help companies support their employees' mental wellbeing."
    
    # Pricing/cost
    elif 'price' in message_lower or 'cost' in message_lower or 'how much' in message_lower:
        return "Our pricing is flexible and scales with your organization size. We offer various plans from small businesses to large enterprises. For specific pricing information, I'd recommend contacting our sales team or starting with our free trial to see how Obeeoma can benefit your organization."
    
    # Features
    elif 'feature' in message_lower or 'what can you do' in message_lower:
        return "Obeeoma offers: 🧠 AI-powered mental health support, 📊 Wellness assessments and tracking, 🚨 Crisis intervention services, 💼 Employee assistance programs, 📈 Organizational analytics, 📱 Mobile app access, and 🔒 Confidential support for all employees."
    
    # Contact information
    elif 'contact' in message_lower or 'email' in message_lower or 'phone' in message_lower:
        return "You can reach our team through our website's contact form, or email us at info@obeeoma.com. We're always happy to discuss how we can support your organization's mental health initiatives!"
    
    # Getting started
    elif 'start' in message_lower or 'begin' in message_lower or 'sign up' in message_lower:
        return "Getting started is easy! You can sign up for a free trial on our website, schedule a demo with our team, or contact us for a personalized consultation. We'll help you set up everything and train your team on using the platform effectively."
    
    # Help/support
    elif 'help' in message_lower or 'support' in message_lower:
        return "I'm here to help! I can tell you about Obeeoma's services, pricing, features, and how to get started. What specific aspect of our mental health platform would you like to know more about?"
    
    # Default response
    else:
        return "Thank you for your interest in Obeeoma! I'm here to help you learn about our mental health platform. I can answer questions about our services, features, pricing, or how to get started. What would you like to know more about?"
