import pymysql
import syslog
from passlib.hash import sha512_crypt

# auth
def pam_sm_authenticate(pamh, flags, argv):
    syslog.syslog("[p] start auth")
    if pamh.authtok is None:
        passmsg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "")
        rsp = pamh.conversation(passmsg)
        pamh.authtok = rsp.resp
    try:
        user = pamh.get_user(None)
        password = pamh.authtok
    except pamh.exception as e:
        return e.pam_result
    syslog.syslog(user)
    if password is None or user is None:
        syslog.syslog("Błędne dane logowania")
        return pamh.PAM_AUTH_ERR
    try:
        db = pymysql.connect(host="localhost", user="postfix", password="haslo do bazy", db="postfix")
        with db.cursor() as cur:
            cur.execute("SELECT password FROM mailbox WHERE username = %s OR local_part = %s", (user, user))
            row = cur.fetchone()
            if row and sha512_crypt.verify(password, row[0]):
                syslog.syslog(f"Witaj {user}")
                return pamh.PAM_SUCCESS
    except Exception as e:
        syslog.syslog(f"Błąd bazy: {str(e)}")
    return pamh.PAM_AUTH_ERR

# auth
def pam_sm_setcred(pamh, flags, argv):
    syslog.syslog("[p] setcred")
    return pamh.PAM_SUCCESS

# session
def pam_sm_open_session(pamh, flags, argv):
    syslog.syslog("session open")
    return pamh.PAM_SUCCESS

# session
def pam_sm_close_session(pamh, flags, argv):
    syslog.syslog("session close")
    return pamh.PAM_SUCCESS

# account
def pam_sm_acct_mgmt(pamh, flags, argv):
    syslog.syslog("[p] acct_mgmt")
    return pamh.PAM_SUCCESS
