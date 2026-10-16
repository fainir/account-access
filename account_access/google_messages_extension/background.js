"use strict";
const host = "com.account_access.google_messages";
let port, sequence=0, polling=false;
const replies = new Map();
function native(body) {
  return new Promise((resolve,reject)=>{
    if (!port) {
      port=chrome.runtime.connectNative(host);
      port.onMessage.addListener(message=>{ const pending=replies.get(message.id); if(pending){clearTimeout(pending.timer);replies.delete(message.id);pending.resolve(message.result);} });
      port.onDisconnect.addListener(()=>{port=null;for(const pending of replies.values()){clearTimeout(pending.timer);pending.reject(new Error("Open Account Access and prepare the SMS connection first."));}replies.clear();});
    }
    const id=++sequence;
    const timer=setTimeout(()=>{replies.delete(id);reject(new Error("The local SMS connection timed out."));},15000);
    replies.set(id,{resolve,reject,timer}); port.postMessage({id,body});
  });
}
async function tabs() {
  return (await chrome.tabs.query({url:"https://messages.google.com/web/conversations*"})).filter(tab=>tab.url==="https://messages.google.com/web/conversations");
}
async function poll() {
  if(polling || !(await chrome.storage.local.get("enabled")).enabled) return;
  polling=true;
  try {
    const result=await native({method:"pending"});
    if(result.source_enabled===false){
      await chrome.storage.local.set({enabled:false});
      await chrome.permissions.remove({origins:["https://messages.google.com/*"]});
      const scripts=await chrome.scripting.getRegisteredContentScripts({ids:["account-access-sms"]});
      if(scripts.length) await chrome.scripting.unregisterContentScripts({ids:["account-access-sms"]});
      return;
    }
    const pages=await tabs();
    if(pages.length!==1) return;
    for(const request of result.pending||[]) {
      let result;
      try {result=await chrome.tabs.sendMessage(pages[0].id,{method:"poll",request});} catch {continue;}
      const base={source:request.source,window:request.window};
      if(result?.lost){await native({method:"lost",...base});continue;}
      if(result?.armed){await native({method:"armed",...base});continue;}
      if(result?.candidates?.length) await native({method:"deliver",...base,messages:result.candidates});
    }
  } catch { /* No page contents, credentials or codes are logged. */ }
  finally {polling=false;}
}
chrome.runtime.onMessage.addListener((message,sender,respond)=>{
  if(sender.id!==chrome.runtime.id || sender.tab || !sender.url?.startsWith(chrome.runtime.getURL("popup.html"))) return false;
  (async()=>{
    if(message.method==="status") return native({method:"accounts"});
    if(message.method!=="connect") throw new Error("Unsupported action.");
    const paired=await tabs();
    if(paired.length!==1) throw new Error("Open exactly one paired Google Messages conversations tab before connecting.");
    const result=await native({method:"connect",account:message.account,fingerprint:message.fingerprint});
    if(result.status!=="CONNECTED") return result;
    const registered=await chrome.scripting.getRegisteredContentScripts({ids:["account-access-sms"]});
    if(!registered.length) await chrome.scripting.registerContentScripts([{id:"account-access-sms",matches:["https://messages.google.com/web/conversations*"],js:["reader.js"],runAt:"document_idle",persistAcrossSessions:true}]);
    for(const tab of await tabs()) await chrome.scripting.executeScript({target:{tabId:tab.id},files:["reader.js"]});
    await chrome.storage.local.set({enabled:true}); poll(); return result;
  })().then(respond).catch(error=>respond({status:"NEEDS_USER",reason:error.message}));
  return true;
});
chrome.alarms.create("sms-reconnect",{periodInMinutes:0.5});
chrome.alarms.onAlarm.addListener(poll);
chrome.runtime.onStartup.addListener(poll);
setInterval(poll,1000);
poll();
