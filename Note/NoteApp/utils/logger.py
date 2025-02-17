import logging

logger = logging.getLogger('custom_logger')

def log_request(request, message):
    user = request.user if request.user.is_authenticated else "Anonymous"
    logger.info(f"User: {user}, Method: {request.method}, Path: {request.path}, Message: {message}")