import time
import json
import hmac
import hashlib
import urllib.request
import urllib.error

API_URL = "http://127.0.0.1:8000"
HMAC_SECRET = "pdx_sec_shield_2026_x89a"

def make_request(url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    req_data = None
    if data is not None:
        req_data = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            raw = response.read().decode("utf-8")
            try:
                body_json = json.loads(raw)
            except Exception:
                body_json = raw
            return response.status, response.headers, body_json
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            body_json = json.loads(body)
        except Exception:
            body_json = body
        return e.code, e.headers, body_json

def sign_request(path: str, headers=None):
    if headers is None:
        headers = {}
    ts = str(int(time.time() * 1000))
    nonce = hashlib.md5(f"{time.time()}_{path}".encode()).hexdigest()
    msg = f"{path}:{ts}:{nonce}"
    sig = hmac.new(HMAC_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    headers.update({
        "X-PDX-Timestamp": ts,
        "X-PDX-Nonce": nonce,
        "X-PDX-Sign": sig
    })
    return headers

def run_tests():
    print("Testing Security Architecture...")

    code, hdrs, _ = make_request(f"{API_URL}/admin")
    assert code == 200
    assert "Permissions-Policy" in hdrs
    assert "https://cdnjs.cloudflare.com" in hdrs.get("Content-Security-Policy", "")
    print("[PASS] Security headers and CSP connect-src verified on HTTP.")

    code_https, hdrs_https, _ = make_request(f"{API_URL}/admin", headers={"X-Forwarded-Proto": "https"})
    assert "Strict-Transport-Security" in hdrs_https
    assert hdrs_https.get("Cross-Origin-Opener-Policy") == "same-origin"
    print("[PASS] HSTS and COOP verified on HTTPS.")

    code, _, _ = make_request(f"{API_URL}/api/admin/login", method="POST", data={"password": "wrong"})
    assert code == 403, f"Expected 403 for unsigned request, got {code}"
    print("[PASS] Unsigned API request successfully blocked with HTTP 403.")

    ts_old = str(int(time.time() * 1000) - 120000)
    nonce = "oldnonce12345"
    sig_old = hmac.new(HMAC_SECRET.encode(), f"/api/admin/login:{ts_old}:{nonce}".encode(), hashlib.sha256).hexdigest()
    code, _, _ = make_request(f"{API_URL}/api/admin/login", method="POST", data={"password": "wrong"}, headers={
        "X-PDX-Timestamp": ts_old,
        "X-PDX-Nonce": nonce,
        "X-PDX-Sign": sig_old
    })
    assert code == 403
    print("[PASS] Expired signature blocked with HTTP 403.")

    headers = sign_request("/api/admin/login")
    code1, _, _ = make_request(f"{API_URL}/api/admin/login", method="POST", data={"password": "wrong"}, headers=dict(headers))
    assert code1 == 401
    code2, _, _ = make_request(f"{API_URL}/api/admin/login", method="POST", data={"password": "wrong"}, headers=dict(headers))
    assert code2 == 403
    print("[PASS] Anti-replay defense verified: replayed nonce rejected with HTTP 403.")

    headers = sign_request("/api/admin/login")
    code, _, res_data = make_request(f"{API_URL}/api/admin/login", method="POST", data={"password": "pladixisback2026@"}, headers=headers)
    assert code == 200
    admin_token = res_data["access_token"]
    print("[PASS] Admin login succeeded with valid signature.")

    headers = sign_request("/api/admin/stats", {"Authorization": f"Bearer {admin_token}"})
    code, _, stats = make_request(f"{API_URL}/api/admin/stats", headers=headers)
    assert code == 200
    print("[PASS] Admin stats retrieved with signature and token.")

    headers = sign_request("/api/logout", {"Authorization": f"Bearer {admin_token}"})
    code, _, _ = make_request(f"{API_URL}/api/logout", method="POST", headers=headers)
    assert code == 200
    print("[PASS] Token revocation endpoint /api/logout succeeded.")

    headers = sign_request("/api/admin/stats", {"Authorization": f"Bearer {admin_token}"})
    code, _, _ = make_request(f"{API_URL}/api/admin/stats", headers=headers)
    assert code == 401
    print("[PASS] Revoked token blocked with HTTP 401.")

    code, _, body = make_request(f"{API_URL}/api/core/_hx99_auth", method="POST", data={
        "_v90x": "test_fingerprint",
        "_k2": 500,
        "_ts": int(time.time() * 1000),
        "_sig": "test_sig",
        "_csrf": "csrf_test"
    })
    assert code != 403 or "Assinatura de segurança ausente" not in str(body), f"Challenge blocked by signature middleware: {body}"
    print(f"[PASS] Antibot challenge endpoint /api/core/_hx99_auth correctly handled (status={code}).")

    print("\nALL SECURITY TESTS PASSED!")

if __name__ == "__main__":
    run_tests()
