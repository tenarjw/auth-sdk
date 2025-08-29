# context.session_fastapi.py
import uuid
from  datetime import datetime

def ses_login(user_id,request=None):
    sid = str(uuid.uuid4().hex)
    request.session['sid'] = sid
    request.session["uid"] = user_id
    request.session['auth_time'] = int(datetime.now().timestamp())

def get_session_uid(request):
    uid = request.session.get("uid")
    try:
        auth_time = request.session['auth_time']
    except:
        auth_time = 0
    return (uid, auth_time)