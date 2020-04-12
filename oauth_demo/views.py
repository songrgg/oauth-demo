from django.http import HttpResponse


def index(request):
    msg = "Hello %s, you're logined." % request.session['user']['name']
    return HttpResponse(msg)
