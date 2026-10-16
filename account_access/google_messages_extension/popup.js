"use strict";
const account=document.querySelector("#account"),button=document.querySelector("#connect"),status=document.querySelector("#status");
const entries=new Map();
(async()=>{
 const result=await chrome.runtime.sendMessage({method:"status"});
 for(const item of result.accounts||[]){entries.set(item.account,item);const option=document.createElement("option");option.value=item.account;option.textContent=item.label;account.append(option);}
 if(!entries.size){button.disabled=true;status.textContent="Open Account Access first and import your reviewed GitHub account. This connector supports that account's login texts only.";}
})().catch(()=>{button.disabled=true;status.textContent="Open Account Access and prepare the Google Messages connection first.";});
button.onclick=async()=>{
 let connected=false;
 try{
  const granted=await chrome.permissions.request({origins:["https://messages.google.com/*"]});if(!granted)return;
  button.disabled=true;const item=entries.get(account.value);
  const result=await chrome.runtime.sendMessage({method:"connect",account:item.account,fingerprint:item.fingerprint});
  connected=result.status==="CONNECTED";
  if(connected) button.textContent="Connected";
  status.textContent=result.status==="CONNECTED"?"Connected. Keep one paired Google Messages conversations tab open. Ask your AI normally.":"The local connection could not finish. Review it in Account Access.";
 }catch{status.textContent="The connection could not finish. Review it in Account Access.";}
 finally{button.disabled=connected;}
};

const sessionAccount=document.querySelector("#session-account"),sessionButton=document.querySelector("#session-connect");
const sessionStatus=document.querySelector("#session-status"),sessionIdentity=document.querySelector("#session-identity");
const sessionEntries=new Map();
function sessionResult(result){
 const reasons={
  browser_session_identity_mismatch:"This tab is signed in to a different GitHub username. Review the account in Account Access.",
  open_github_signed_in_tab:"Open your signed-in GitHub tab, then reopen this helper.",
  browser_login_required:"GitHub did not accept the copied sign-in. Sign in normally in Chrome before connecting again.",
  browser_state_unrecognized:"GitHub's signed-in page did not match the reviewed connection. Review it in Account Access.",
  invalid_browser_session_state:"Chrome returned an unsupported session format. The existing connection is preserved.",
  browser_session_verification_failed:"The local verification browser could not finish. Review it in Account Access.",
  browser_session_request_expired_or_changed:"The local request expired or changed. Start a new connection in Account Access.",
  browser_session_partition_unsupported:"This Chrome session uses partitioned cookies, which this connection does not yet support."
 };
 return result.status==="SESSION_CONNECTED"?"Connected and verified. Return to your AI and ask normally.":
   reasons[result.reason]||"The session could not be verified. Review this connection in Account Access.";
}
function showIdentity(){
 const entry=sessionEntries.get(sessionAccount.value);
 sessionIdentity.textContent=entry?"Expected GitHub username: "+entry.username:"";
}
sessionAccount.onchange=showIdentity;
(async()=>{
 const result=await chrome.runtime.sendMessage({method:"session-status"});
 for(const item of result.accounts||[]){
  sessionEntries.set(item.account,item);const option=document.createElement("option");
  option.value=item.account;option.textContent=item.label;sessionAccount.append(option);
 }
 sessionButton.disabled=!sessionEntries.size;showIdentity();
 if(result.outcome && result.outcome.expires>Date.now()) sessionStatus.textContent=sessionResult(result.outcome);
 else if(!sessionEntries.size) sessionStatus.textContent="Start this connection in the Account Access app first.";
})().catch(()=>{sessionStatus.textContent="Open Account Access and update this browser helper first.";});
sessionButton.onclick=async()=>{
 let connected=false;
 try{
  // The permission prompt is tied to this explicit owner click. Nothing is
  // copied automatically when the helper is installed or the popup is opened.
  const item=sessionEntries.get(sessionAccount.value);
  const request={account:item.account,request:item.id,fingerprint:item.fingerprint};
  // Request in the original user gesture. Record the intent concurrently so
  // approval still completes in the background if Chrome closes this popup.
  const preparation=chrome.runtime.sendMessage({method:"session-prepare",...request});
  const approval=chrome.permissions.request({permissions:["cookies"],origins:["https://github.com/*"]});
  const prepared=await preparation,granted=await approval;
  if(prepared.status!=="AWAITING_PERMISSION"){sessionStatus.textContent=sessionResult(prepared);return;}
  if(!granted)return;
  sessionButton.disabled=true;sessionStatus.textContent="Checking your signed-in account…";
  const result=await chrome.runtime.sendMessage({method:"session-connect",...request});
  connected=result.status==="SESSION_CONNECTED";
  sessionStatus.textContent=sessionResult(result);
 }catch{sessionStatus.textContent="The connection could not finish. Review it in Account Access.";}
 finally{sessionButton.disabled=connected;}
};
