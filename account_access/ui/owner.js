"use strict";
let capability = location.hash.slice(1);
history.replaceState(null, "", "/");
const output = document.querySelector("#message");
const accounts = document.querySelector("#accounts");
const node = (tag, text, className) => { const el = document.createElement(tag); if(text) el.textContent=text; if(className) el.className=className; return el; };
async function call(path, body) {
  const response = await fetch(path, {method:body ? "POST" : "GET", headers:{Authorization:"Bearer "+capability, ...(body ? {"Content-Type":"application/json"} : {})}, ...(body ? {body:JSON.stringify(body)} : {})});
  const result = await response.json();
  if(!response.ok) throw new Error(result.reason || "Request could not be completed");
  return result;
}
function button(label, callback, className) {
  const el=node("button",label,className); el.type="button"; el.onclick=async()=>{el.disabled=true;try{const result=await callback();output.textContent=result.status;await refresh();}catch(error){output.textContent=error.message;}finally{el.disabled=false;}};return el;
}
async function refresh() {
  if(!capability){output.textContent="Open this console using the owner setup command to unlock it.";return;}
  const state=await call("/owner/state");
  document.querySelector("#environment").textContent=state.environment==="controlled-demo" ? "Configured local test connections. Results do not validate access to personal accounts." : state.environment==="public-example"?"Public testing accounts. Results do not validate access to personal accounts.":state.environment==="mixed"?"Mixed connections. Public examples and local tests are labeled on each account.":"Local account access. Permissions below apply to this service.";
  accounts.replaceChildren();
  if(!state.accounts.length) accounts.append(node("p","No accounts configured yet. Add a reviewed service adapter in owner setup to begin.","empty"));
  for(const account of state.accounts){
    const card=node("article",null,"account");card.append(node("h2",account.label));card.append(node("p",account.account+" · "+account.route+" · "+(account.connected?"Session saved":"Connection needed"),"status"));
    if(["public-example","controlled-demo"].includes(account.environment))card.append(node("p","Example connection. This does not validate access to a personal account.","status"));
    const existing=state.grants.filter(x=>x.account===account.account);card.append(node("p","Granted access: "+(existing.length?existing.map(x=>x.principal+" → "+x.operation+(x.expires?" until "+new Date(x.expires*1000).toLocaleString():"")).join("; "):"none"),"status"));
    for(const challenge of account.challenges) card.append(node("p",challenge.required_action+" Reference: "+challenge.id,"challenge"));
    const row=node("div",null,"row");row.append(button("Connect or repair",()=>call("/owner/connect",{account:account.account})));row.append(button("Revoke access",()=>call("/owner/revoke",{account:account.account}),"danger"));card.append(row);
    const details=node("details");details.append(node("summary",account.route==="browser"?"Save a password for permitted login recovery":"Configure application credential"));const form=node("form");const inputs={};
    for(const field of account.route==="browser"?["username","password"]:["client_secret"]){const input=node("input");input.type=field==="username"?"text":"password";input.autocomplete=field==="username"?"username":"new-password";input.placeholder=field==="username"?"Email or username":field==="password"?"Password":"Application secret";input.setAttribute("aria-label",input.placeholder);inputs[field]=input;form.append(input);}
    const save=node("button","Save locally");save.type="submit";form.append(save);form.onsubmit=async e=>{e.preventDefault();const body={account:account.account};for(const field in inputs)body[field]=inputs[field].value;try{await call("/owner/credential",body);for(const input of Object.values(inputs))input.value="";output.textContent="Saved locally.";details.open=false;}catch(error){output.textContent=error.message;}};details.append(form);card.append(details);
    const grant=node("div",null,"row");const select=node("select");select.setAttribute("aria-label","Agent permission");for(const principal of state.principals){const option=node("option",principal);option.value=principal;select.append(option);}grant.append(select);const ops=node("div",null,"operations");const boxes=[];for(const op of account.operations){const label=node("label");const box=node("input");box.type="checkbox";box.value=op.name;box.checked=true;boxes.push(box);label.append(box,node("span",op.description));ops.append(label);}card.append(ops);grant.append(button("Allow selected operations",()=>call("/owner/grant",{account:account.account,principal:select.value,operations:boxes.filter(x=>x.checked).map(x=>x.value)})));card.append(grant);accounts.append(card);
  }
  const running=Object.values(state.connection_jobs).some(x=>x.status==="RUNNING");
  if(running){output.textContent="Complete the connection in the sign-in browser. This page will update afterward.";setTimeout(()=>refresh().catch(error=>output.textContent=error.message),2000);}
}
refresh().catch(error=>output.textContent=error.message);
