import datetime
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib import messages


class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:  # Ensure the user is logged in
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            last_activity = request.session.get('last_activity', None)

            if last_activity:
                last_activity = datetime.datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S')
                if (datetime.datetime.now() - last_activity).seconds > 120:
                    logout(request)  # Log the user out
                    # Show a message and redirect to the login page
                    messages.info(request, "Your session has expired due to inactivity. Please log in again.")
                    return redirect('login')  # Replace 'login' with your login view name or URL

            # Update the session with the current activity time
            request.session['last_activity'] = current_time

        response = self.get_response(request)
        return response
