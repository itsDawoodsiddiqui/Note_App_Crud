from datetime import datetime
from django.utils.timezone import make_aware
import logging

# Set up a logger
logger = logging.getLogger(__name__)

class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Capture the timestamp, IP address, and user ID
        timestamp = make_aware(datetime.now())  # Current time in timezone-aware format
        ip_address = self.get_client_ip(request)
        user_id = request.user.id if request.user.is_authenticated else None
        
        # Log the request details
        logger.info(f"Timestamp: {timestamp}, IP: {ip_address}, User ID: {user_id}")
        
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Get the client's IP address from the request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
