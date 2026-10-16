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
