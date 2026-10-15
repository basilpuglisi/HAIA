"""
Browser test for the CBG Gateway, Agent Model 2 edition v10. Runs the real review screens in headless
Chromium with a virtual passkey authenticator (the browser's own WebAuthn
code, with the fingerprint check simulated).

It carries the 22 browser checks of v9 and adds the checks of plan step 8: before
the browser asks the passkey to sign, it checks the challenge against the exact
envelope text the gateway sent and the text on screen against the text being
signed. A dishonest gateway is simulated by rewriting its responses in the
browser (page.route). Every page also counts its calls to navigator.credentials.get,
so a refused signature can be shown never to have reached the passkey.

Run: python test_cbg_gateway_model2_browser_v10.py
Needs: pip install playwright, and a Chromium build Playwright can launch.
"""

import base64
import hashlib
import html as html_lib
import json
import os
import re
import sys
import tempfile
import threading
import time

import httpx
import uvicorn
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cbg_gateway_model2_v10 as cg  # noqa: E402

PORT = 8765
ORIGIN = f"http://localhost:{PORT}"
RESULTS = []
TOKEN = "agent-token-for-tests-0123456789"

# v10: texts the HTML parser could change on the way to the screen.
FIXTURES = {
    "lead": "\nLeading newline answer.\nSecond line of the answer.",
    "crlf": "Windows line endings.\r\nSecond line.\r\nThird line, and a lone return\rhere.",
    "html": "Tags <b>bold</b> & <script>x()</script> \"quoted\" 'single' &amp; &lt; end.",
    "astral": "Outside the Basic Multilingual Plane: \U0001F600 \U00010348 \U0001D11E end.",
}
# Counts every call to navigator.credentials.get on each page load.
COUNT_GETS = """(() => { window.__credGets = 0; const c = navigator.credentials; if (!c) return;
const g = c.get.bind(c); c.get = function (o) { window.__credGets++; return g(o); }; })()"""


def check(label, condition, detail=""):
    RESULTS.append((label, bool(condition), detail))


def attempt(label, fn):
    """A v10 check that is recorded whatever happens, so the run against the unmodified
    v9 copy lists it as a failure instead of stopping."""
    try:
        ok, detail = fn()
    except Exception as ex:
        ok, detail = False, f"raised {type(ex).__name__}: {str(ex)[:80]}"
    check(label, ok, detail)


def fixture(name):
    def stream(model, messages):
        yield FIXTURES[name]
        yield cg.Completion(name, "end_turn")
    return stream


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def canonical_text(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def dishonest(route, change):
    """Act as a gateway that lies: pass the begin request through, then rewrite the
    answer with change(j) before the browser sees it."""
    resp = route.fetch()
    j = resp.json()
    change(j)
    route.fulfill(response=resp, body=json.dumps(j), content_type="application/json")


def wrong_challenge(j):
    """The challenge no longer hashes the envelope text the gateway sent."""
    opts = json.loads(j["options"])
    opts["challenge"] = b64u(hashlib.sha256(b"an envelope the governor never saw").digest())
    j["options"] = json.dumps(opts)


def other_final_text(j):
    """A consistent envelope, challenge included, that names a final text not on screen."""
    other = hashlib.sha256("a final text that is not on screen".encode()).hexdigest()
    if "envelope_json" in j:
        env = json.loads(j["envelope_json"])
        env["final_output_hash"] = other
        j["envelope_json"] = canonical_text(env)
        j["envelope"] = env
        opts = json.loads(j["options"])
        opts["challenge"] = b64u(hashlib.sha256(j["envelope_json"].encode("utf-8")).digest())
        j["options"] = json.dumps(opts)
    else:
        j["envelope"]["final_output_hash"] = other


def first_words(text):
    return " ".join(text.split()[:cg.CONFIRM_WORDS])


def tagged(name):
    def stream(model, messages):
        yield f"{name} answer. "
        yield from cg.mock_stream(model, messages)
    return stream


def main(screenshot_dir=None):
    tmp = tempfile.mkdtemp()
    calls = {"flaky": 0}

    def flaky(model, messages):
        calls["flaky"] += 1
        if calls["flaky"] == 1:
            raise RuntimeError("service unavailable")
        yield from tagged("flaky")(model, messages)
    provs = {n: tagged(n) for n in ("alpha", "beta", "gamma", "delta", "nav")}
    provs["flaky"] = flaky
    provs.update({n: fixture(n) for n in FIXTURES})
    gw = cg.Gateway(os.path.join(tmp, "gw.db"), "localhost", ORIGIN, providers=provs, enrollment_code="CODE",
                    agent_token=TOKEN, confirm="all", anchor_sinks=[cg.file_sink(os.path.join(tmp, "anchors.jsonl"))])
    server = uvicorn.Server(uvicorn.Config(cg.create_app(gw), host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    agent = httpx.Client(base_url=ORIGIN, headers={"Authorization": f"Bearer {TOKEN}"})

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context()
        context.add_init_script(COUNT_GETS)
        page = context.new_page()
        cdp = context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        auth_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True}})["authenticatorId"]

        def msg(contains, timeout=8000, pg=None):
            pg = pg or page
            pg.wait_for_function(
                "t => document.getElementById('msg') && document.getElementById('msg').textContent.includes(t)",
                arg=contains, timeout=timeout)
            return pg.inner_text("#msg")

        def task_page_until(task_id, text, seconds=10, pg=None):
            pg = pg or page
            end = time.time() + seconds
            while time.time() < end:
                pg.goto(f"{ORIGIN}/task/{task_id}")
                if text in pg.inner_text("main"):
                    return True
                time.sleep(0.2)
            return False

        def decide(task_id, cp, decision, why, text_for_words, edit=None, form=None, wait_for="Signed"):
            page.goto(f"{ORIGIN}/task/{task_id}")
            page.check(f"input[name='decision-{cp}'][value='{decision}']")
            if edit is not None:
                page.fill(f"#edit-{cp}", edit)
            if form is not None:
                page.select_option(f"#form-{cp}", form)
            page.fill(f"#why-{cp}", why)
            if text_for_words is not None:
                page.fill(f"#confirm-{cp}", first_words(text_for_words))
            page.click(f"button[data-act=decide][data-cp='{cp}']")
            return msg(wait_for)

        def settled(pg=None, timeout=8000):
            """The message a signing attempt ends with (not the passkey prompt), its class,
            and how many times the page called navigator.credentials.get."""
            pg = pg or page
            pg.wait_for_function(
                "() => { const m = document.getElementById('msg'); return m && m.textContent.length > 0"
                " && !m.textContent.startsWith('Confirm with your passkey'); }", timeout=timeout)
            return (pg.inner_text("#msg"), pg.eval_on_selector("#msg", "e => e.className"),
                    pg.evaluate("() => window.__credGets"))

        def try_decide(task_id, cp, decision, why, text_for_words, edit=None, before_click=None):
            """A decision from the page that never raises; returns (message, class, credentials.get calls)."""
            try:
                page.goto(f"{ORIGIN}/task/{task_id}")
                page.check(f"input[name='decision-{cp}'][value='{decision}']")
                if edit is not None:
                    page.fill(f"#edit-{cp}", edit)
                page.fill(f"#why-{cp}", why)
                # The whole text, typed: a token of symbols only (an emoji, an ampersand) is no
                # word, so the first eight tokens can hold fewer than eight words.
                page.fill(f"#confirm-{cp}", " ".join(text_for_words.split()))
                if before_click:
                    before_click()
                page.click(f"button[data-act=decide][data-cp='{cp}']")
                return settled()
            except Exception as ex:
                return (f"raised {type(ex).__name__}: {str(ex)[:60]}", "", None)

        def answer_of(task_id, slot):
            return gw.task_state(task_id)["steps"][0]["answers"].get(slot)

        # enrollment and sign-in
        page.goto(f"{ORIGIN}/enroll")
        page.fill("#gid", "basil")
        page.fill("#code", "CODE")
        page.click("text=Create passkey")
        check("Browser: governor enrolls a passkey", "Enrolled basil" in msg("Enrolled"))
        page.goto(f"{ORIGIN}/login")
        page.click("text=Sign in with passkey")
        page.wait_for_url(f"{ORIGIN}/")
        check("Browser: governor signs in with the passkey", "Signed in as" in page.inner_text("header"))

        # agent proposes: two RECCLIN roles, three platforms each, a Navigator held out
        plats = [{"provider": n, "model": "m1"} for n in ("alpha", "beta", "gamma")]
        proposal = {
            "title": "Article 14 summary", "scope": "Summarize EU AI Act Article 14",
            "criteria": "Primary source only", "constraints": "No legal advice",
            "risk_class": "moderate", "destinations": ["basilpuglisi.com draft"],
            "governor_id": "basil", "expires_in_minutes": 60, "navigator": {"provider": "nav", "model": "n1"},
            "steps": [{"role": "Researcher", "prompt_template": "Research EU AI Act Article 14.", "platforms": plats},
                      {"role": "Editor", "prompt_template": "Edit for clarity: {previous}", "platforms": plats}]}
        task = agent.post("/api/tasks", json=proposal).json()["task_id"]

        # BEFORE: the governor sets the scope, the Navigator model, and adds a fourth platform
        page.goto(f"{ORIGIN}/task/{task}")
        new_scope = "Summarize EU AI Act Article 14 for the board, citing the article text"
        page.fill("#m-scope", new_scope)
        page.fill("#m-nav-model", "n2")
        page.fill("#m-plat-0", "alpha:m1, beta:m1, gamma:m1, delta:m1")
        page.fill("#m-confirm", first_words(new_scope))
        page.click("text=Authorize this manifest (BEFORE)")
        check("Browser: governor establishes and signs the BEFORE manifest", "Signed" in msg("Signed"))
        m = gw.task_state(task)["manifest"]
        check("Browser: the signed manifest carries the governor's scope, Navigator, and platforms",
              m["scope"] == new_scope and m["navigator"] == {"provider": "nav", "model": "n2"}
              and len(m["steps"][0]["platforms"]) == 4
              and m["governor_changes"] == ["navigator", "platforms", "scope"], str(m.get("governor_changes")))
        check("Browser: step 1 goes to four platforms and every answer waits for the governor",
              task_page_until(task, "4 of 4 platform answers to review"))
        body = page.inner_text("main")
        outs = gw.task_state(task)["steps"][0]["outputs"]
        check("Browser: every answer is shown in full with its RECCLIN field check",
              all(outs[j]["body"]["output"].split("\n")[0][:60] in body for j in range(4))
              and body.count("RECCLIN fields:") == 4)
        if screenshot_dir:
            page.set_viewport_size({"width": 1100, "height": 1400})
            page.screenshot(path=os.path.join(screenshot_dir, "cbg_gateway_review_screen_v9.png"), full_page=True)

        # AFTER on each answer
        edit = "Article 14 requires effective human oversight of high-risk AI systems."
        cp = [outs[j]["id"] for j in range(4)]
        decide(task, cp[0], "modify", "Tightened to the regulation text", None, edit=edit, wait_for="first")
        check("Browser: a decision without the typed first words is refused",
              page.eval_on_selector("#msg", "e => e.className") == "bad"
              and 0 not in gw.task_state(task)["steps"][0]["answers"], page.inner_text("#msg")[:70])
        decide(task, cp[0], "modify", "Tightened to the regulation text", outs[0]["body"]["output"], edit=edit)
        check("Browser: governor modifies answer 1; it goes to the Navigator",
              task_page_until(task, "Sent to the Navigator (turn 1)"))
        decide(task, cp[1], "reject", "Cites no source", outs[1]["body"]["output"], form="deny")
        check("Browser: governor rejects answer 2; it is kept from the Navigator",
              task_page_until(task, "Kept from the Navigator"))
        decide(task, cp[2], "accept", "Matches the article", outs[2]["body"]["output"])
        decide(task, cp[3], "reject", "Wrong article", outs[3]["body"]["output"],
               edit="My own summary of Article 14.", form="replace_with_human_input")
        check("Browser: the Navigator's synthesis waits for the governor",
              task_page_until(task, "the Navigator synthesis"))
        st = gw.task_state(task)
        turns = st["steps"][0]["turns"]
        check("Browser: approved answers reached the Navigator one at a time, in decision order; the rejected one never",
              [gw.ledger.get(t["body"]["forwarded_id"])["body"]["envelope"]["slot"] for t in turns] == [0, 2, 3]
              and outs[1]["body"]["output"] not in " ".join(t["body"]["item"] for t in turns))
        body = page.inner_text("main")
        check("Browser: the page shows each Navigator turn", "Turn 1" in body and "Turn 3 (synthesis)" in body)
        ft = st["steps"][0]["final_turn"]
        decide(task, ft["id"], "accept", "Synthesis keeps the dissent", ft["body"]["output"])
        check("Browser: the signed synthesis starts step 2 on three platforms",
              task_page_until(task, "3 of 3 platform answers to review"))

        st = gw.task_state(task)
        outs2 = st["steps"][1]["outputs"]
        for j in range(3):
            decide(task, outs2[j]["id"], "accept", "Reads correctly", outs2[j]["body"]["output"])
        task_page_until(task, "the Navigator synthesis")
        ft2 = gw.task_state(task)["steps"][1]["final_turn"]
        final = ft2["body"]["output"] + "\nGovernor's closing line."
        decide(task, ft2["id"], "modify", "Added a closing line", ft2["body"]["output"], edit=final)
        check("Browser: the governor signs a modified final synthesis; the task is ready to release",
              task_page_until(task, "approved; ready to release"))
        r = agent.post(f"/api/tasks/{task}/release", json={"destination": "basilpuglisi.com draft"})
        bundle = r.json()
        problems = cg.verify_bundle(bundle, gw.gateway_public_key()) if r.status_code == 200 else ["release failed"]
        check("Agent releases the governor's text; every browser passkey signature verifies offline",
              not problems and bundle["final_text"] == final and len(bundle["answer_decisions"][0]) == 4,
              "; ".join(problems))

        # DURING: a platform fails; the governor restarts it from the page with a direction
        restart_task = agent.post("/api/tasks", json=dict(proposal, title="Restart test", steps=[dict(
            proposal["steps"][0], platforms=[{"provider": n, "model": "m1"} for n in ("alpha", "beta", "flaky")])]
        )).json()["task_id"]
        page.goto(f"{ORIGIN}/task/{restart_task}")
        page.fill("#m-confirm", first_words(proposal["scope"]))
        page.click("text=Authorize this manifest (BEFORE)")
        msg("Signed")
        check("Browser: the page names the platform that failed", task_page_until(restart_task, "provider error"))
        page.click("text=Restart or redirect answer 3 (flaky) (DURING)")
        page.fill("#direction-2", "Quote the article text.")
        page.click("button[data-act=restart][data-slot='2']")
        msg("Signed")
        check("Browser: the governor restarts the failed platform with a signed direction",
              task_page_until(restart_task, "3 of 3 platform answers to review")
              and "Quote the article text." in gw.task_state(restart_task)["steps"][0]["outputs"][2]["body"]["task_text"])

        # high risk: a second governor countersigns in a separate browser on a separate device
        code = gw.issue_enrollment_code("carol")
        page.goto(f"{ORIGIN}/governors")
        page.click("text=Approve enrollment")
        check("Browser: basil approves carol's enrollment on the Governors page", "Signed" in msg("Signed"))
        ctx2 = browser.new_context()
        ctx2.add_init_script(COUNT_GETS)
        page2 = ctx2.new_page()
        cdp2 = ctx2.new_cdp_session(page2)
        cdp2.send("WebAuthn.enable")
        cdp2.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
        page2.goto(f"{ORIGIN}/enroll")
        page2.fill("#gid", "carol")
        page2.fill("#code", code)
        page2.click("text=Create passkey")
        msg("Enrolled", pg=page2)
        page2.goto(f"{ORIGIN}/login")
        page2.click("text=Sign in with passkey")
        page2.wait_for_url(f"{ORIGIN}/")
        high = dict(proposal, title="Board memo", risk_class="high", second_governor_id="carol",
                    destinations=["board"], steps=proposal["steps"][:1])
        th = agent.post("/api/tasks", json=high).json()["task_id"]
        page.goto(f"{ORIGIN}/task/{th}")
        page.fill("#m-confirm", first_words(high["scope"]))
        page.click("text=Authorize this manifest (BEFORE)")
        msg("Signed")
        task_page_until(th, "3 of 3 platform answers to review")
        oh = gw.task_state(th)["steps"][0]["outputs"]
        for j in range(3):
            decide(th, oh[j]["id"], "accept", "Checked", oh[j]["body"]["output"])
        task_page_until(th, "the Navigator synthesis")
        fh = gw.task_state(th)["steps"][0]["final_turn"]
        decide(th, fh["id"], "accept", "Checked", fh["body"]["output"])
        r = agent.post(f"/api/tasks/{th}/release", json={"destination": "board"})
        check("Browser: a high-risk task cannot leave before the second governor signs",
              r.status_code == 409, r.json().get("error", "")[:60])

        # v10, step 8: a dishonest gateway sends a countersign challenge that is not the
        # hash of the envelope text; carol's browser stops before the passkey is asked.
        def countersign_lie():
            page2.route("**/api/human/countersign/begin", lambda route: dishonest(route, wrong_challenge))
            try:
                page2.goto(f"{ORIGIN}/task/{th}")
                page2.check("input[name='cs-decision'][value='accept']")
                page2.fill("#cs-why", "Independent check done")
                page2.fill("#cs-confirm", first_words(fh["body"]["output"]))
                page2.click("text=Sign countersignature with passkey")
                text, cls, gets = settled(page2)
            finally:
                page2.unroute("**/api/human/countersign/begin")
            return (text.startswith("Stopped") and cls == "bad" and gets == 0
                    and not gw.task_state(th)["countersigns"], f"{text[:60]} (credentials.get {gets})")
        attempt("Browser v10 step 8 (a): a countersign challenge that is not the hash of the envelope text is "
                "refused before the passkey is asked", countersign_lie)
        page2.goto(f"{ORIGIN}/task/{th}")
        page2.check("input[name='cs-decision'][value='accept']")
        page2.fill("#cs-why", "Independent check done")
        page2.fill("#cs-confirm", first_words(fh["body"]["output"]))
        page2.click("text=Sign countersignature with passkey")
        msg("Signed", pg=page2)
        r = agent.post(f"/api/tasks/{th}/release", json={"destination": "board"})
        problems = cg.verify_bundle(r.json(), gw.gateway_public_key()) if r.status_code == 200 else [r.text[:60]]
        check("Browser: the second governor countersigns on their own device; every signature verifies",
              not problems and [c["envelope"]["governor_id"] for c in r.json().get("countersigns", [])] == ["carol"],
              "; ".join(problems))
        ctx2.close()

        # v10, step 8: the challenge and the text on screen, checked before the passkey is asked
        fx_prop = dict(proposal, title="Text fixtures", steps=[dict(proposal["steps"][0], platforms=[
            {"provider": n, "model": "m1"} for n in FIXTURES])])
        fx = agent.post("/api/tasks", json=fx_prop).json()["task_id"]
        page.goto(f"{ORIGIN}/task/{fx}")
        page.fill("#m-confirm", first_words(proposal["scope"]))
        page.click("text=Authorize this manifest (BEFORE)")
        msg("Signed")
        task_page_until(fx, "4 of 4 platform answers to review")
        fo = gw.task_state(fx)["steps"][0]["outputs"]
        slot = {n: j for j, n in enumerate(FIXTURES)}
        cpx = {n: fo[slot[n]]["id"] for n in FIXTURES}

        def decide_lie():
            page.route("**/api/human/decide/begin", lambda route: dishonest(route, wrong_challenge))
            try:
                text, cls, gets = try_decide(fx, cpx["lead"], "accept", "Checked", FIXTURES["lead"])
            finally:
                page.unroute("**/api/human/decide/begin")
            return (text.startswith("Stopped") and "challenge" in text and cls == "bad" and gets == 0
                    and answer_of(fx, slot["lead"]) is None, f"{text[:60]} (credentials.get {gets})")
        attempt("Browser v10 step 8 (a): a decision challenge that is not the hash of the envelope text is refused "
                "before the passkey is asked", decide_lie)

        def final_lie():
            page.route("**/api/human/decide/begin", lambda route: dishonest(route, other_final_text))
            try:
                text, cls, gets = try_decide(fx, cpx["lead"], "accept", "Checked", FIXTURES["lead"])
            finally:
                page.unroute("**/api/human/decide/begin")
            return (text == "Stopped: the gateway prepared a different final text than the one on screen."
                    and gets == 0 and answer_of(fx, slot["lead"]) is None, f"{text[:60]} (credentials.get {gets})")
        attempt("Browser v10 step 8 (b): an envelope naming a final text other than the one on screen is refused "
                "(the v9 final-text branch, now behind a matching challenge)", final_lie)

        def doctored_pre():
            shown = "\nA text the gateway shows but the governor would not be signing."

            def doctor(route):
                resp = route.fetch()
                body = resp.text()
                out = html_lib.escape(FIXTURES["html"])
                body = re.sub(r"(<pre[^>]*>\n?)" + re.escape(out) + "</pre>",
                              lambda m: m.group(1) + html_lib.escape(shown) + "</pre>", body, count=1)
                route.fulfill(response=resp, body=body, content_type="text/html; charset=utf-8")
            page.route(f"{ORIGIN}/task/{fx}", doctor)
            try:
                text, cls, gets = try_decide(fx, cpx["html"], "accept", "Checked", FIXTURES["html"])
                doctored = shown.strip() in page.inner_text("main")
            finally:
                page.unroute(f"{ORIGIN}/task/{fx}")
            return (doctored and text.startswith("Stopped") and "on screen" in text and gets == 0
                    and answer_of(fx, slot["html"]) is None, f"{text[:60]} (credentials.get {gets})")
        attempt("Browser v10 step 8 (c): a doctored <pre> beside a correct JSON copy is refused before the passkey "
                "is asked", doctored_pre)

        def late_edit():
            cp = cpx["astral"]

            def hook():
                page.evaluate("""cp => { const f = window.fetch; window.fetch = async (...a) => { const r = await f(...a);
                    if (String(a[0]).includes('/api/human/decide/begin')) { const el = document.getElementById('edit-' + cp);
                    el.value = el.value + ' changed after it was sent'; } return r; }; }""", cp)
            text, cls, gets = try_decide(fx, cp, "modify", "Tightened", FIXTURES["astral"],
                                         edit=FIXTURES["astral"] + " Governor's note.", before_click=hook)
            return (text.startswith("Stopped") and "edited text" in text and gets == 0
                    and answer_of(fx, slot["astral"]) is None, f"{text[:60]} (credentials.get {gets})")
        attempt("Browser v10 step 8 (d): a modify whose edit box changes after the text was sent is refused",
                late_edit)

        def edit_box_starts_right():
            page.goto(f"{ORIGIN}/task/{fx}")
            boxes = {n: page.query_selector(f"#edit-{cpx[n]}") for n in FIXTURES}
            got = {n: boxes[n].input_value() if boxes[n] else None for n in FIXTURES}
            want = {n: t.replace("\r\n", "\n").replace("\r", "\n") for n, t in FIXTURES.items()}
            return got == want, json.dumps([n for n in FIXTURES if got[n] != want[n]])
        attempt("Browser v10 step 8 (d): each edit box starts with the answer as written, leading newline included",
                edit_box_starts_right)

        def fixtures_decide():
            results = {}
            results["lead"] = try_decide(fx, cpx["lead"], "accept", "Checked", FIXTURES["lead"])
            results["crlf"] = try_decide(fx, cpx["crlf"], "accept", "Checked", FIXTURES["crlf"])
            edited = FIXTURES["html"] + " Governor's note: <i>kept</i> & checked."
            results["html"] = try_decide(fx, cpx["html"], "modify", "Added a note", FIXTURES["html"], edit=edited)
            results["astral"] = try_decide(fx, cpx["astral"], "accept", "Checked", FIXTURES["astral"])
            want = {"lead": FIXTURES["lead"], "crlf": FIXTURES["crlf"], "html": edited, "astral": FIXTURES["astral"]}
            got = {n: (answer_of(fx, slot[n]) or {"body": {"final_text": None}})["body"]["final_text"] for n in FIXTURES}
            ok = all(r[0].startswith("Signed") for r in results.values()) and got == want
            return ok, "; ".join(f"{n}: {results[n][0][:24]}" for n in FIXTURES)
        attempt("Browser v10 step 8: answers with a leading newline, CR LF, HTML special characters, and characters "
                "outside the Basic Multilingual Plane decide successfully, each with the exact text signed",
                fixtures_decide)

        def synthesis_shown():
            if not task_page_until(fx, "the Navigator synthesis"):
                return False, gw.task_state(fx)["status"][:60]
            ft = gw.task_state(fx)["steps"][0]["final_turn"]
            text, cls, gets = try_decide(fx, ft["id"], "accept", "Synthesis checked", ft["body"]["output"])
            return text.startswith("Signed") and gets == 1, f"{text[:60]} (credentials.get {gets})"
        attempt("Browser v10 step 8: the Navigator synthesis passes the same checks and is signed with one passkey call",
                synthesis_shown)

        # no fingerprint, no authorization
        task2 = agent.post("/api/tasks", json=dict(proposal, title="UV test")).json()["task_id"]
        cdp.send("WebAuthn.setUserVerified", {"authenticatorId": auth_id, "isUserVerified": False})
        page.goto(f"{ORIGIN}/task/{task2}")
        page.fill("#m-confirm", first_words(proposal["scope"]))
        page.click("text=Authorize this manifest (BEFORE)")
        page.wait_for_function("() => document.getElementById('msg').className === 'bad'", timeout=8000)
        check("Browser: passkey without the fingerprint check is refused",
              not gw.task_state(task2)["authorized"], page.inner_text("#msg")[:90])
        cdp.send("WebAuthn.setUserVerified", {"authenticatorId": auth_id, "isUserVerified": True})
        page.goto(f"{ORIGIN}/")
        page.click("text=Sign out")
        page.wait_for_url(f"{ORIGIN}/login", timeout=8000)
        page.goto(f"{ORIGIN}/")
        check("Browser: sign out ends the session", page.url.endswith("/login"), page.url)
        browser.close()

    server.should_exit = True
    width = max(len(r[0]) for r in RESULTS)
    for label, passed, detail in RESULTS:
        print(f"{'PASS' if passed else 'FAIL'}  {label.ljust(width)}  {detail}")
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)} of {len(RESULTS)} browser checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
