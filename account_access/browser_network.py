"""Preserve Chromium's transport while checking every native redirect response."""

import base64
from urllib.parse import urljoin

from playwright.sync_api import Error as PlaywrightError

from .errors import AccessError


class ResponseGuard:
    """Private CDP pipe only; no debugging port or agent-visible browser handle.

    Playwright routes see only the first request in a redirect chain. Pause
    native responses before Chromium follows Location, validating its exact
    destination and resulting method. Child frames/workers retain the separate
    bounded fetch guard; only requests owned by an attached main frame may use
    native transport.
    """

    def __init__(self, context, permitted, failure, response, payload=None, proof=None):
        self.context = context
        self.permitted = permitted
        self.failure = failure
        self.response = response
        self.payload = payload
        self.proof = proof
        self.sessions = {}

    def attach(self, page):
        try:
            session = self.context.new_cdp_session(page)
            hops = {}
            main_frame = session.send("Page.getFrameTree")["frameTree"]["frame"]["id"] if self.payload or self.proof else None
            if self.proof:
                # Capture the immutable request chain before its paused response;
                # neither a DOM change nor a response alone proves dispatch.
                session.on("Network.requestWillBeSent", lambda event: self.proof.observe(event, session, main_frame))
                session.send("Network.enable")
            session.on("Fetch.requestPaused", lambda event: self.paused(session, hops, event, main_frame))
            session.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]})
            self.sessions[page] = session
            page.on("close", lambda: self.sessions.pop(page, None))
        except PlaywrightError:
            # Never fall back to unguarded native requests after attachment fails.
            if not page.is_closed():
                page.close()

    def native(self, request):
        try:
            frame = request.frame
            return frame.parent_frame is None and frame.page in self.sessions
        except PlaywrightError:
            return False  # Dedicated-worker requests do not have a frame.

    def provenance(self, request):
        try:
            frame = request.frame
            return {"attachment": self.sessions.get(frame.page),
                    "main_document": (frame.parent_frame is None and frame.page in self.sessions
                                      and request.is_navigation_request() and request.resource_type == "document")}
        except PlaywrightError:
            return {"attachment": None, "main_document": False}

    def paused(self, session, hops, event, main_frame=None):
        request_id = event["requestId"]
        chain = event.get("networkId", request_id)
        request = event["request"]
        url, method = request["url"], request["method"]
        kind = event["resourceType"].lower()
        hop = hops.get(chain, 0)
        provenance = {"attachment": session, "chain": chain,
                      "main_document": kind == "document" and event.get("frameId") == main_frame}

        def permitted(target, verb):
            return (self.permitted(target, verb, kind, **provenance) if self.proof
                    else self.permitted(target, verb, kind))

        def abort(reason, target=url, redirected=False):
            self.failure(target, method, reason, kind, redirected)
            hops.pop(chain, None)
            session.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})

        try:
            reason = permitted(url, method)
            if reason:
                abort(reason, redirected=hop > 0)
                return
            status = event.get("responseStatusCode")
            if status is None:
                abort("transport")
                return
            locations = [item["value"] for item in event.get("responseHeaders", []) if item["name"].lower() == "location"]
            if len(locations) > 1:
                abort("destination")
                return
            location = locations[0] if locations else None
            self.response(url, method, status, kind, urljoin(url, location) if location else None)
            if self.proof:
                self.proof.response(url=url, method=method, status=status, locations=locations,
                    attachment=session, frame=event.get("frameId"), chain=chain, kind=kind,
                    main_document=provenance["main_document"], hop=hop)
            if status >= 400:
                self.failure(url, method, "http_" + str(status), kind, hop > 0)
            if status in {301, 302, 303, 307, 308}:
                if not location:
                    abort("missing_location")
                    return
                target = urljoin(url, location)
                next_method = ("GET" if method != "HEAD" and (
                    status == 303 or (status in {301, 302} and method == "POST")) else method)
                reason = permitted(target, next_method)
                if reason:
                    abort(reason, target, True)
                    return
                if hop >= 5:
                    abort("redirect_limit", target, True)
                    return
                hops[chain] = hop + 1
            else:
                hops.pop(chain, None)
                length = next((item["value"] for item in event.get("responseHeaders", [])
                               if item["name"].lower() == "content-length"), "0")
                if length.isdecimal() and int(length) > 8_000_000:
                    abort("response_size")
                    return
                if method != "HEAD" and status not in {204, 205, 304}:
                    body = session.send("Fetch.getResponseBody", {"requestId": request_id})
                    payload = (base64.b64decode(body["body"], validate=True) if body.get("base64Encoded")
                               else body["body"].encode("utf-8"))
                    if len(payload) > 8_000_000:
                        abort("response_size")
                        return
                    if self.payload:
                        headers = {item["name"].lower(): item["value"] for item in event.get("responseHeaders", [])}
                        self.payload(url, kind, payload, headers, event.get("frameId") == main_frame)
            session.send("Fetch.continueResponse", {"requestId": request_id})
        except (PlaywrightError, ValueError, AccessError):
            try:
                abort("transport")
            except PlaywrightError:
                pass  # A closed page/context cannot send any further request.
