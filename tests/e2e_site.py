"""End-to-end test of the reserved path /site (website next to the server, see bridge/server/routes/site.py).

- A real Bridge server answers /site and /site/... with the "no website assigned" page (404, HTML).
- The admin dashboard has the Website button that opens /site/.
- No Bridge route uses /site, and a route that would is refused at start (check_reserved).

Run from the project folder:  python tests/e2e_site.py
"""
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
PORT = 8231
URL = f"http://127.0.0.1:{PORT}"

results = {"ok": 0, "fail": 0}


def check(name, condition, info=None):
    if condition:
        results["ok"] += 1
        print(f"  OK    {name}")
    else:
        results["fail"] += 1
        print(f"  FAIL  {name}  {info if info is not None else ''}")


def offline_checks():
    from fastapi import APIRouter, FastAPI
    from bridge.server.routes import site

    check("is_reserved /site", site.is_reserved("/site"))
    check("is_reserved /site/x/y", site.is_reserved("/site/x/y"))
    check("not reserved /sites", not site.is_reserved("/sites"))
    check("not reserved /client/site", not site.is_reserved("/client/site"))

    app = FastAPI()
    app.include_router(site.Router)
    try:
        site.check_reserved(app)
        check("own placeholder routes pass the check", True)
    except RuntimeError as error:
        check("own placeholder routes pass the check", False, error)

    bad = APIRouter(prefix="/site")

    @bad.get("/clients")
    async def clashing():
        return {}

    app.include_router(bad)
    try:
        site.check_reserved(app)
        check("a Bridge route under /site is refused (via app)", False, "no error")
    except RuntimeError as error:
        check("a Bridge route under /site is refused (via app)", "/site/clients" in str(error), error)
    try:
        site.check_reserved(bad)
        check("a Bridge route under /site is refused (via router)", False, "no error")
    except RuntimeError as error:
        check("a Bridge route under /site is refused (via router)", "/site/clients" in str(error), error)


def online_checks():
    log = open(os.path.join(ROOT, "tests", "site_server.log"), "w")
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "run_server.py"), str(PORT), "admin-site"],
                            cwd=ROOT, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                if httpx.get(URL + "/server/status", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        else:
            check("server starts", False)
            return
        check("server starts (create_app accepts all routes)", True)

        for path in ("/site", "/site/", "/site/index.html", "/site/a/b/c.css"):
            response = httpx.get(URL + path, timeout=5)
            check(f"{path} -> placeholder 404 HTML", response.status_code == 404
                  and "keine Website zugewiesen" in response.text
                  and response.headers.get("content-type", "").startswith("text/html"),
                  (response.status_code, response.text[:80]))

        admin = httpx.get(URL + "/admin", timeout=5).text
        check("dashboard has the Website button to /site/", 'id="siteBtn"' in admin and 'href="/site/"' in admin)

        # the app itself: no route other than the placeholder touches /site
        sys.path.insert(0, ROOT)
        from bridge.server import app as app_module
        from bridge.server.routes import site
        import inspect
        source = inspect.getsource(app_module)
        check("create_app runs check_site_reserved", "check_site_reserved(app," in source)
        check("status/landing page still at /", httpx.get(URL + "/", timeout=5).status_code == 200)
        check("site placeholder is no client path (works while starting)",
              not any(p.startswith(site.SITE_PATH) for p in app_module.CLIENT_PATHS))
    finally:
        try:
            proc.stdin.close()
            proc.wait(25)
        except Exception:
            proc.kill()
        log.close()


if __name__ == "__main__":
    print("== /site offline ==")
    offline_checks()
    print("== /site online ==")
    online_checks()
    print(f"\n{results['ok']} OK, {results['fail']} FAIL")
    sys.exit(1 if results["fail"] else 0)
