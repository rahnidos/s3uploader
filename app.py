from flask import Flask, request, session, redirect, url_for
import oci
from dotenv import load_dotenv
from datetime import timedelta
import hmac
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
from pathlib import Path
import logging
import os



load_dotenv()  


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# configuration for blacklist file and failed-attempt counters
BLACKLIST_FILE = Path(os.getenv('BLACKLIST_FILE', 'blocked_ips.txt'))
MAX_FAILED_LOGIN = int(os.getenv('MAX_FAILED_LOGIN', '5'))
failed_attempts = {}
blocked_ips = set()
_blacklist_lock = threading.Lock()

# debug: show configuration on startup
log.info("Configuration: BLACKLIST_FILE=%s, MAX_FAILED_LOGIN=%s", BLACKLIST_FILE, MAX_FAILED_LOGIN)
try:
    log.info("Blacklist file resolved to (resolved): %s", BLACKLIST_FILE.resolve())
except Exception:
    log.debug("Failed to resolve blacklist path; it may not exist yet")
# ensure directory and empty file exist at startup
try:
    BLACKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    BLACKLIST_FILE.touch(exist_ok=True)
    log.info("Blacklist file resolved to: %s", BLACKLIST_FILE.resolve())
except Exception:
    log.exception("Error creating/accessing blacklist file: %s", BLACKLIST_FILE)

def load_blacklist():
    global blocked_ips
    try:
        if BLACKLIST_FILE.exists():
            with BLACKLIST_FILE.open('r', encoding='utf-8') as f:
                blocked_ips = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            log.info("Loaded %d entries into blacklist from %s", len(blocked_ips), BLACKLIST_FILE.resolve())
        else:
            blocked_ips = set()
            log.info("Blacklist file does not exist (using empty set)")
    except Exception:
        log.exception("Error loading blacklist: %s", BLACKLIST_FILE)
        blocked_ips = set()

def append_to_blacklist(ip):
    with _blacklist_lock:
        try:
            log.info("Adding IP to blacklist: %s", ip)
            blocked_ips.add(ip)
            BLACKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
            # open and write, force flush+fsync to ensure disk write
            with BLACKLIST_FILE.open('a', encoding='utf-8') as f:
                f.write(ip + '\n')
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    # fsync may not be available on some systems/FS — just log
                    log.debug("fsync failed (may not be available on this system): %s", BLACKLIST_FILE)
            log.info("Wrote IP to blacklist file: %s", BLACKLIST_FILE.resolve())
        except Exception:
            log.exception("Failed to write IP to blacklist: %s", ip)

# load blacklist at startup
load_blacklist()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'change_this_to_a_strong_secret')
app.permanent_session_lifetime = timedelta(days=90)

# secure cookie/session settings
app.config.update(
    SESSION_COOKIE_SECURE=True,      # works only if you serve over HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# initialize OCI Object Storage client (prefer env-based config, fall back to ~/.oci/config)
try:
    oci_config = {
        "tenancy": os.getenv('OCI_TENANCY'),
        "user": os.getenv('OCI_USER'),
        "fingerprint": os.getenv('OCI_FINGERPRINT'),
        "key_file": os.getenv('OCI_KEY_FILE'),
        "region": os.getenv('OCI_REGION', 'eu-frankfurt-1')
    }
    object_storage = oci.object_storage.ObjectStorageClient(oci_config)
    try:
        OCI_NAMESPACE = object_storage.get_namespace().data
        log.info("OCI Object Storage namespace: %s", OCI_NAMESPACE)
    except Exception:
        OCI_NAMESPACE = None
        log.debug("Failed to determine OCI namespace at startup")
except Exception:
    log.exception("Failed to initialize OCI Object Storage client")
    object_storage = None
    OCI_NAMESPACE = None

BUCKET = os.getenv('OCI_BUCKET_NAME')
DOMAIN = os.getenv('REVERSE_PROXY_DOMAIN')

# flask-limiter configuration
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.getenv('RATELIMIT_STORAGE_URI', 'memory://'),  # use redis://... in prod
    default_limits=[]  # no global limits — apply per-route
)

@app.route('/', methods=['GET'])
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return '''
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" multiple>
        <button>Upload</button>
    </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    ip = get_remote_address()
    log.info("Entering /login from IP: %s (blocked_ips contains: %s)", ip, bool(ip in blocked_ips))

    if ip in blocked_ips:
        log.info("Blocked IP: %s", ip)
        return 'Twoje IP jest zablokowane. Skontaktuj się z administratorem.', 403

    if request.method == 'POST':
        supplied = request.form.get('pass', '')
        expected = os.getenv('UPLOAD_PASS', '')
        log.debug("POST /login from %s supplied_len=%d", ip, len(supplied))

        if hmac.compare_digest(supplied, expected):
            # success -> clear counter and log in
            with _blacklist_lock:
                failed_attempts.pop(ip, None)
            session.permanent = True
            session['logged_in'] = True
            log.info("Successful login from %s", ip)
            return redirect(url_for('index'))

        # incorrect password -> increment counter and possibly block
        need_block = False
        with _blacklist_lock:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            log.info("Failed login from %s — count=%d", ip, failed_attempts[ip])
            if failed_attempts[ip] >= MAX_FAILED_LOGIN:
                need_block = True

        if need_block:
            log.info("Exceeded limit for %s, calling append_to_blacklist", ip)
            append_to_blacklist(ip)  # called outside of locking in caller code
            log.info("Blocked IPs now: %s", blocked_ips)
            return 'Zbyt wiele nieudanych prób — IP zablokowane', 403

        return 'Błędne hasło', 403

    return '''
    <form method="post">
        <input type="password" name="pass" placeholder="hasło">
        <button>Zaloguj</button>
    </form>
    '''


@app.route('/', methods=['POST'])
@limiter.limit("60 per hour")            # upload rate limit per IP
def upload():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        return 'Brak pliku', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'Brak nazwy pliku', 400
    
    try:
        respobj=object_storage.put_object(
            namespace_name=OCI_NAMESPACE,
            bucket_name=BUCKET,
            object_name=file.filename,
            put_object_body=file
        )
        print(respobj)
        url = f'https://{DOMAIN}/{file.filename}'
        return f'<h1>OK: {url}</h1><a href="{url}">Link</a>'
    except Exception as e:
        return f'Błąd: {e}', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)