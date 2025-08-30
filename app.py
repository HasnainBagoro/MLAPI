from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib, pandas as pd, json, re
from collections import Counter
from math import log2

# ---- load artifacts ----
MODEL_PATH = "url_model.pkl"
THRESH_PATH = "threshold.json"
pipe = joblib.load(MODEL_PATH)
with open(THRESH_PATH, "r") as f:
    THRESH = json.load(f)["threshold"]

# ---- feature code (keep in sync with training) ----
ip_pattern = re.compile(r'^(?:http[s]?://)?(\d{1,3}\.){3}\d{1,3}')
tld_pattern = re.compile(r'\.([a-z]{2,24})(?:[\/:]|$)', re.IGNORECASE)

def shannon_entropy(s: str):
    if not s: return 0.0
    c = Counter(s); p = [v/len(s) for v in c.values()]
    return -sum(pi*log2(pi) for pi in p)

def extract_url_features(u: str):
    u = str(u).strip()
    u_noprot = re.sub(r'^https?://','',u,flags=re.IGNORECASE)
    parts = u_noprot.split('/')
    domain = parts[0] if parts else u_noprot
    path = '/' + '/'.join(parts[1:]) if len(parts)>1 else ''
    f = {}
    f['url_len'] = len(u)
    f['url_noprot_len'] = len(u_noprot)
    f['domain_len'] = len(domain)
    f['path_len'] = len(path)
    f['count_dots'] = u.count('.')
    f['count_hyphen'] = u.count('-')
    f['count_at'] = u.count('@')
    f['count_qmark'] = u.count('?')
    f['count_eq'] = u.count('=')
    f['count_underscore'] = u.count('_')
    f['count_slash'] = u.count('/')
    f['count_percent'] = u.count('%')
    f['num_digits'] = sum(c.isdigit() for c in u)
    f['digit_ratio'] = f['num_digits'] / (f['url_len'] + 1e-9)
    f['has_ip'] = 1 if ip_pattern.search(u) else 0
    m = tld_pattern.search(domain)
    f['tld'] = m.group(1).lower() if m else ''
    f['subdomain_count'] = max(domain.count('.') - 1, 0)
    f['entropy'] = shannon_entropy(u_noprot)
    f['tld_freq'] = 0  # we don't know corpus freq at inference; 0 is fine
    return f

NUMERIC_COLS = ['url_len','url_noprot_len','domain_len','path_len','count_dots','count_hyphen',
                'count_at','count_qmark','count_eq','count_underscore','count_slash','count_percent',
                'num_digits','digit_ratio','has_ip','subdomain_count','entropy','tld_freq']

class URLRequest(BaseModel):
    url: str

app = FastAPI(title="Malicious URL Detector API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/predict")
def predict(req: URLRequest):
    u = req.url
    f = extract_url_features(u)
    row = {'url': u}; row.update({k: f[k] for k in NUMERIC_COLS})
    X = pd.DataFrame([row])
    proba = float(pipe.predict_proba(X)[0][1])
    is_malicious = bool(proba >= THRESH)
    return {"url": u, "is_malicious": is_malicious, "malicious_probability": proba, "threshold": THRESH}
