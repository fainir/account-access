(() => {
  "use strict";
  if (globalThis.accountAccessSmsReader) return;
  globalThis.accountAccessSmsReader = true;
  const windows = new Map();
  const template = "{code} is your GitHub authentication code.";
  function rows() {
    if (location.origin !== "https://messages.google.com" || location.pathname !== "/web/conversations" || location.search || location.hash) return null;
    if (!document.querySelector("mws-conversations-list")) return null;
    const navigation = document.querySelector("mws-conversations-list nav");
    if (!navigation || navigation.scrollTop !== 0) return null;
    const elements = Array.from(document.querySelectorAll("mws-conversation-list-item")).slice(0, 50);
    return {head:elements[0]?.querySelector("a[data-e2e-conversation]")?.getAttribute("href"), keys:elements.map(row=>row.querySelector("a[data-e2e-conversation]")?.getAttribute("href")), matches:elements.flatMap((row, index) => {
      const text = row.querySelector("mws-conversation-snippet")?.textContent?.trim() || "";
      if (!/^\d{6} is your GitHub authentication code\.$/.test(text)) return [];
      const key = row.querySelector("a[data-e2e-conversation]")?.getAttribute("href") || "";
      if (!/^\/web\/conversations\/[^?#\s]+$/.test(key)) return [];
      const age = row.querySelector("mws-relative-timestamp [aria-label]")?.getAttribute("aria-label") || "";
      return [{key, text, age, index}];
    })};
  }
  async function poll(request) {
    const now = Date.now() / 1000;
    for (const [id, state] of windows) if (state.expires < now) windows.delete(id);
    if (request.template !== template || !/^[a-f0-9]{32}$/.test(request.window) || !Number.isFinite(request.expires) || request.expires < now || request.expires > now + 125) return {unavailable:true};
    const current = rows();
    if (!current) return {unavailable:true};
    let state = windows.get(request.window);
    if (!state) {
      if (request.phase !== "baseline") return {lost:true};
      if (windows.size >= 8) return {unavailable:true};
      if (!current.head) return {unavailable:true};
      state = {expires:request.expires, baseline:new Map(current.matches.map(row=>[row.key,row.text])), head:current.head, started:now, lost:false};
      windows.set(request.window, state);
    }
    if (request.phase === "baseline") return {armed:true};
    const boundary = current.keys.indexOf(state.head);
    if(state.lost || boundary < 0) return {lost:true};
    const candidates = [];
    for (const row of current.matches) {
      if (row.index > boundary || state.baseline.get(row.key) === row.text) continue;
      let fresh = /^(?:now|just now|0 min ago)$/i.test(row.age);
      const seconds = row.age.match(/^(\d{1,3}) sec ago$/i);
      if (seconds) fresh = Number(seconds[1]) <= Math.min(120, now - state.started + 5);
      if (!fresh) continue; // Unknown/localized ages and older cached rows stop safely.
      const bytes = new TextEncoder().encode(row.key + "\0" + row.text);
      const id = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map(b=>b.toString(16).padStart(2,"0")).join("");
      candidates.push({id, code:row.text.slice(0,6), observed_at:now});
    }
    return {candidates};
  }
  document.addEventListener("scroll",()=>{for(const state of windows.values())state.lost=true;},true);
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== chrome.runtime.id || message?.method !== "poll") return false;
    poll(message.request).then(respond).catch(()=>respond({unavailable:true}));
    return true;
  });
})();
