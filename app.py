import os, hashlib, hmac, json, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from apprise import Apprise

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

LOGGER = logging.getLogger("webhook_relay")
APPRISE_VERBOSE = os.getenv("APPRISE_VERBOSE", "false").lower() == "true"
APPRISE_LOGGER = logging.getLogger("apprise")
if APPRISE_VERBOSE:
    APPRISE_LOGGER.setLevel(logging.DEBUG)
    LOGGER.setLevel(logging.DEBUG)
else:
    APPRISE_LOGGER.setLevel(logging.INFO)

APP = FastAPI()
APPRISE_TARGETS = [u.strip() for u in os.getenv("APPRISE_URLS","").split(",") if u.strip()]
SHARED_SECRET = os.getenv("SHARED_SECRET", "")  # optional
REQUIRE_SECRET = os.getenv("REQUIRE_SECRET", "true").lower() == "true"
POLICY_ALLOWLIST = [p.strip() for p in os.getenv("POLICY_ALLOWLIST","").split(",") if p.strip()]  # optional csv
HOST_LIMIT = int(os.getenv("HOST_LIMIT","25"))  # truncate long lists in messages

def _apprise_client():
    ap = Apprise(debug=APPRISE_VERBOSE)
    for u in APPRISE_TARGETS:
        ap.add(u)
    return ap


def _describe_plugin(plugin):
    try:
        return plugin.url(privacy=not APPRISE_VERBOSE)
    except Exception:
        return repr(plugin)


def _notify_with_logging(ap, body, title):
    try:
        sequential_calls, parallel_calls = ap._create_notify_calls(body, title)
    except TypeError:
        LOGGER.exception("Apprise failed to prepare notification calls")
        return False

    total = len(sequential_calls) + len(parallel_calls)
    LOGGER.info("Dispatching notification via Apprise to %d target(s)", total)

    def dispatch(server, kwargs):
        target = _describe_plugin(server)
        LOGGER.debug("Notifying %s", target)
        try:
            result = server.notify(**kwargs)
        except Exception:
            LOGGER.exception("Notification attempt via %s raised an exception", target)
            return False

        if result:
            LOGGER.debug("Notification via %s reported success", target)
        else:
            LOGGER.warning("Notification via %s reported failure", target)
        return bool(result)

    ok = True
    for server, kwargs in sequential_calls:
        ok = dispatch(server, kwargs) and ok

    if parallel_calls:
        LOGGER.debug("Notifying %d target(s) in parallel", len(parallel_calls))
        with ThreadPoolExecutor() as executor:
            future_map = {
                executor.submit(dispatch, server, kwargs): server
                for server, kwargs in parallel_calls
            }
            for future in as_completed(future_map):
                ok = future.result() and ok

    return ok

def _fmt_host_line(h):
    # expected keys from Fleet example: id, display_name, url
    name = h.get("display_name") or f"id:{h.get('id')}"
    url  = h.get("url","")
    return f"- {name} {f'({url})' if url else ''}".rstrip()

def render_message(payload: dict) -> str:
    policy = payload.get("policy", {})
    hosts = payload.get("hosts", []) or []
    ts = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()

    name = policy.get("name","<unknown policy>")
    desc = policy.get("description","")
    query = policy.get("query","")
    failing_count = policy.get("failing_host_count") or len(hosts)
    passing_count = policy.get("passing_host_count")

    head = [
        f"Fleet Policy Failed: {name}",
        f"Time (UTC): {ts}",
        f"Failing hosts in this event: {len(hosts)} | Total failing count: {failing_count}",
    ]
    if passing_count is not None:
        head.append(f"Passing host count: {passing_count}")
    if desc:
        head.append(f"Description: {desc}")

    # host lines (truncated)
    lines = [*head, "", "Hosts:"]
    for h in hosts[:HOST_LIMIT]:
        lines.append(_fmt_host_line(h))
    if len(hosts) > HOST_LIMIT:
        lines.append(f"...and {len(hosts)-HOST_LIMIT} more")

    # include query (useful for audits)
    lines.extend(["", "Policy query:", query.strip()[:2000]])  # safety cap

    return "\n".join(lines)

def verify_secret(req: Request, body: bytes):
    """
    Two options:
    - Static shared token via header X-Webhook-Token
    - Optional HMAC signature: X-Hub-Signature-256: sha256=<hmac>
      (If SHARED_SECRET is set; you can add this in your reverse proxy)
    """
    if not SHARED_SECRET:
        if REQUIRE_SECRET:
            raise HTTPException(401, "Secret required but not configured")
        return

    token = req.headers.get("X-Webhook-Token")
    if token and hmac.compare_digest(token, SHARED_SECRET):
        return

    sig = req.headers.get("X-Hub-Signature-256", "")
    if sig.startswith("sha256="):
        digest = hmac.new(SHARED_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig[7:], digest):
            return

    raise HTTPException(401, "Invalid or missing signature/token")

@APP.post("/fleet")
async def fleet_webhook(request: Request):
    body = await request.body()
    verify_secret(request, body)

    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    # optional filter to a subset of policies
    policy_name = (payload.get("policy") or {}).get("name","")
    if POLICY_ALLOWLIST and policy_name not in POLICY_ALLOWLIST:
        return JSONResponse({"ok": True, "ignored": True, "reason": "policy not allowlisted"})

    message = render_message(payload)
    LOGGER.debug("Rendered notification message:\n%s", message)
    LOGGER.debug("Apprise targets: %s", APPRISE_TARGETS)

    ap = _apprise_client()

    try:
        ok = _notify_with_logging(ap, message, "Fleet Policy Failure")
    except Exception:
        LOGGER.exception("Apprise notification pipeline raised an unhandled exception")
        raise HTTPException(500, "Apprise notification failed")

    if not ok:
        LOGGER.error("One or more Apprise notifications failed")

    return JSONResponse({"ok": bool(ok)})
