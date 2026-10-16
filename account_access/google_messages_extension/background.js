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
  if(sender.id!==chrome.runtime.id || sender.tab || sender.url!==chrome.runtime.getURL("popup.html")) return false;
  (async()=>{
    if(message.method==="session-status" && Object.keys(message).length===1) return native({method:"session-accounts"});
    if(message.method==="session-connect") return connectBrowserSession(message);
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
chrome.runtime.onStartup.addListener(()=>{clearSessionPermission();poll();});
chrome.alarms.create("session-cleanup",{periodInMinutes:0.5});
chrome.alarms.onAlarm.addListener(alarm=>{if(alarm.name==="session-cleanup" && !sessionBusy) clearSessionPermission();});
setInterval(poll,1000);
poll();

let sessionBusy=false;
async function clearSessionPermission(){
  await chrome.permissions.remove({permissions:["cookies"],origins:["https://github.com/*"]});
}
async function connectBrowserSession(message){
  if(sessionBusy || Object.keys(message).sort().join(",")!=="account,fingerprint,method,request")
    return {status:"DENIED",reason:"browser_session_not_available"};
  sessionBusy=true;
  // A separate native process keeps session verification from blocking fresh
  // SMS delivery on the persistent SMS port. Raw cookies are never logged.
  try{
    const pending=await native({method:"session-accounts"});
    const selected=(pending.accounts||[]).find(item=>item.account===message.account && item.id===message.request
      && item.fingerprint===message.fingerprint && item.origin==="https://github.com");
    if(!selected || !(await chrome.permissions.contains({permissions:["cookies"],origins:["https://github.com/*"]})))
      return {status:"DENIED",reason:"browser_session_request_expired_or_changed"};
    const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
    if(!tab?.url || new URL(tab.url).origin!==selected.origin)
      return {status:"NEEDS_USER",reason:"open_github_signed_in_tab"};
    const stores=await chrome.cookies.getAllCookieStores();
    const store=stores.find(item=>item.tabIds.includes(tab.id));
    if(!store) return {status:"NEEDS_USER",reason:"browser_session_store_unavailable"};
    const cookies=await chrome.cookies.getAll({url:"https://github.com/",storeId:store.id});
    if(cookies.some(item=>item.partitionKey)) return {status:"NEEDS_USER",reason:"browser_session_partition_unsupported"};
    const state={cookies:cookies.map(item=>({name:item.name,value:item.value,domain:item.domain,path:item.path,
      expires:item.expirationDate??-1,httpOnly:item.httpOnly,secure:item.secure,
      sameSite:({no_restriction:"None",lax:"Lax",strict:"Strict"})[item.sameSite]||"Lax"})),origins:[]};
    if(new TextEncoder().encode(JSON.stringify(state)).length>48000)
      return {status:"NEEDS_USER",reason:"invalid_browser_session_state"};
    const current=await chrome.tabs.get(tab.id);
    if(!current.url || new URL(current.url).origin!==selected.origin)
      return {status:"NEEDS_USER",reason:"browser_session_tab_changed"};
    return await chrome.runtime.sendNativeMessage(host,{id:0,body:{method:"session-import",account:selected.account,
      request:selected.id,fingerprint:selected.fingerprint,origin:selected.origin,state}}).then(reply=>reply.result);
  }catch{return {status:"NEEDS_USER",reason:"browser_session_verification_failed"};}
  finally{try{await clearSessionPermission();}finally{sessionBusy=false;}}
}
