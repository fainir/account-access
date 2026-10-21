"use strict";
const capability=location.hash.slice(1);
history.replaceState(null,"","/");
const el=id=>document.getElementById(id);
const message=text=>el("message").textContent=text;
let state=null;
let googleMessagesPreparation=null;
let googleMessagesSetup=null;
const setupDrafts=new Map(),setupOperations=new Map();
let setupEpoch=0;
function clearSetupDraft(key,cancelOperation=true){const draft=setupDrafts.get(key);if(draft){draft.secrets.forEach(field=>field.value="");draft.active=false;setupDrafts.delete(key);}if(cancelOperation&&setupOperations.has(key))setupOperations.get(key).cancelled=true;}
function clearSetupDrafts(){setupEpoch++;for(const key of setupDrafts.keys())clearSetupDraft(key);for(const operation of setupOperations.values())operation.cancelled=true;}
function clearMaskedInputs(){document.querySelectorAll('input[type="password"]').forEach(field=>field.value="");}
window.addEventListener("pagehide",()=>{clearMaskedInputs();clearSetupDrafts();});
let healthTimer=null,healthBusy=false,locallyPaused=false;
let deviceEmailReview=null,deviceEmailReviewNode=null,deviceEmailPreviewButton=null,deviceEmailEpoch=0;
function clearDeviceEmailReview(){const previous=deviceEmailReview;deviceEmailReview=null;deviceEmailEpoch++;deviceEmailReviewNode?.remove();deviceEmailReviewNode=null;if(deviceEmailPreviewButton)deviceEmailPreviewButton.disabled=locallyPaused;deviceEmailPreviewButton=null;if(previous?.id)call("/owner/device-email/discard",{id:previous.id}).catch(()=>{});}
async function call(path,body){
 const r=await fetch(path,{method:body?"POST":"GET",headers:{Authorization:"Bearer "+capability,...(body?{"Content-Type":"application/json"}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const value=await r.json();if(!r.ok)throw new Error(value.reason||"Please try again.");return value;
}
const friendly={account_already_added:"This account is already added. Use Manage permissions to repair it.",install_your_agent_first:"Finish automatic setup first.",existing_skill_would_be_overwritten:"Another skill uses this name. Review it before installing Account Access.",browser_execution_failed:"The website is temporarily unavailable. Use Manage permissions to try again.",connection_not_completed:"Complete sign-in using Manage permissions.",password_not_connected:"Save the login for this account first."};
Object.assign(friendly,{mailbox_connection_failed:"The mail server did not accept this connection. Check the email address and application password.",mailbox_not_connected:"Reconnect this mailbox in Verification.",invalid_mailbox_setup:"Check the email address, TLS IMAP server, port and application password.",mailbox_already_connected:"This mailbox is already saved. Use Update app password or Check connection.",mailbox_source_mismatch:"Choose the mailbox for this website's approved email address and server.",mailbox_binding_changed:"This website or mailbox connection changed. Reopen Verification and choose the checked mailbox again.",invalid_mailbox_binding:"Reopen Verification and choose a checked mailbox for this website.",mailbox_binding_unsupported:"This website's email connection needs a supported connector before it can use a saved mailbox."});
Object.assign(friendly,{mailbox_identity_check_required:"Check your saved Google connection, then review the website's email connection. No app password is needed.",mailbox_connection_retry_required:"Google access is saved. Try Check Google connection again; Account Access can renew it without another consent prompt."});
Object.assign(friendly,{password_export_encrypted:"Choose an unencrypted Bitwarden JSON export. Keep it on this computer and remove it after importing.",mailbox_scope_not_allowed:"Google returned broader access than this connection permits. The publisher must check its Google application; your existing connection is preserved.",mailbox_oauth_renewal_unavailable:"Google did not provide renewable access. Reconnect once so approved email-code logins can continue after access expires."});
Object.assign(friendly,{password_file_too_large:"The password export is too large. Export fewer accounts and try again.",invalid_password_export:"The password file could not be read. Export a fresh UTF-8 CSV or unencrypted Bitwarden JSON file and try again.",unsupported_password_export:"Choose a supported password CSV or unencrypted Bitwarden JSON export."});
Object.assign(friendly,{import_connector_changed:"This account's connection changed after the import review. Choose the password file again and review its current permissions.",import_authenticator_changed:"This account's authenticator changed after the import review. Choose the password file again before replacing its authenticator key."});
Object.assign(friendly,{pypi_manual_setup_unavailable:"Manual PyPI setup is unavailable in this pilot. Use the reviewed automatic route; your saved login is preserved.",login_challenge_changed:"The website's verification route changed. Account Access stopped before another attempt; the connector needs review."});
Object.assign(friendly,{device_email_setup_changed:"This account changed during the review. Choose its current mailbox connection again.",device_email_mailbox_changed:"This mailbox changed during the review. Check its connection, then choose it again.",device_email_mailbox_unavailable:"Connect and check a mailbox first, then choose it for PyPI device emails.",device_email_setup_expired:"This review expired. Choose the mailbox again to create a fresh review.",device_email_setup_incomplete:"The connection result could not be confirmed. Review its current state in Verification before trying again.",invalid_device_email_setup:"Choose this account's connected mailbox again in Verification.",device_email_setup_limit:"There are too many pending email reviews. Cancel an earlier review or wait briefly."});
function deviceEmailProblem(error){message(friendly[error.message]||"The email connection could not be confirmed. Open Verification to review its current state.");}
Object.assign(friendly,{password_sync_not_connected:"This password source was removed. Refresh Password sync before connecting it again.",password_sync_connection_changed:"This connection changed while the form was open. Reopen Password sync and use its current Replace token action.",password_sync_connector_changed:"The account connection changed. Review the current website and password source before reconnecting.",password_sync_identity_mismatch:"The replacement token returned a different account. Your existing login and source are preserved.",invalid_password_sync_link:"Check the password source details and replacement token. Reopen Password sync if this form is out of date."});
Object.assign(friendly,{password_source_access_removed:"The password manager rejected this token or its read access. Your existing connection is preserved.",password_source_unavailable:"The password manager could not be reached. Your existing connection is preserved; try again when it is online.",password_source_item_changed:"The password-manager item no longer matches this approved login. Review the original item before reconnecting.",password_source_runtime_unavailable:"The password-manager helper is unavailable. Repair the local installation before reconnecting."});
Object.assign(friendly,{bitwarden_connection_invalid:"Check your Bitwarden server region, personal API key and master password. Enter them only in this local setup form.",bitwarden_vault_consent_required:"Review and allow local vault access before connecting Bitwarden.",bitwarden_protected_worker_required:"Bitwarden sync requires the protected Account Access installation. Update or repair the app first.",bitwarden_connection_not_found:"This Bitwarden connection was removed. Connect it again in Password sync.",bitwarden_connection_changed:"This Bitwarden connection changed. Reopen Password sync before linking or disconnecting it."});
Object.assign(friendly,{invalid_authenticator_seed:"Use the website's original authenticator setup key or otpauth link. A current six-digit code cannot connect your authenticator.",unsupported_authenticator_settings:"This authenticator needs six-digit SHA-1 TOTP with a 30-second period. Open Verification in the desktop app to review its setup."});
function bitwardenProblem(error){message(error.message==="password_source_access_removed"?"Bitwarden did not accept this connection. Check the personal API key, region and master password, or reconnect if access was revoked.":friendly[error.message]||"Bitwarden setup could not be confirmed. Reopen Password sync to review its current state.");}
function clearBitwardenSetup(){document.querySelectorAll("[data-bitwarden-secret]").forEach(field=>field.value="");document.querySelectorAll("[data-bitwarden-consent]").forEach(field=>field.checked=false);document.querySelectorAll("[data-bitwarden-active]").forEach(form=>delete form.dataset.bitwardenActive);}
function problem(e){message(friendly[e.message]||"Setup needs attention: "+e.message);}
function text(tag,value){const n=document.createElement(tag);n.textContent=value;return n;}
function renderRecoveryHealth(health){
 if(locallyPaused)return;
 const recovery=health?.status;
 el("service-status").textContent=recovery==="RETRYING"?"Retrying background recovery":recovery==="STOPPED"?"Background recovery stopped":recovery==="UNAVAILABLE"?"Local app unavailable":recovery==="RUNNING"?"Running on your computer":"Local setup is open";
 const notice=el("recovery-health");notice.hidden=!["RETRYING","STOPPED","UNAVAILABLE"].includes(recovery);
 notice.textContent=recovery==="RETRYING"?"Background recovery hit an internal problem and is retrying automatically. Your saved connections and completed task steps are preserved.":recovery==="STOPPED"?"Background recovery stopped. Use Repair installation in the app menu to restart it. Your saved connections are preserved.":recovery==="UNAVAILABLE"?"Account Access is not responding. Open the app to reconnect.":"";
}
async function checkRecoveryHealth(){
 if(healthBusy||document.hidden||locallyPaused)return;
 healthBusy=true;
 try{renderRecoveryHealth(await call("/owner/health"));}catch{renderRecoveryHealth({status:"UNAVAILABLE"});}finally{healthBusy=false;}
}
function permission(){const choice=state.catalog.find(x=>x.id===el("service").value);el("permission").textContent=choice?"Allowed: "+choice.operations.map(x=>x.description).join("; "):"";}
let view="accounts";
let adding=false;
const labels={codex:"Codex",claude:"Claude Code"};
const isExample=account=>["controlled-demo","public-example"].includes(account.environment);
const isReady=account=>account.connected&&account.portable_ready&&!account.challenges?.length;
function prompt(){return state.accounts.some(x=>!isExample(x)&&isReady(x))?"Summarize the approved information from my connected services and save the results as one task.":state.accounts.some(x=>isExample(x)&&isReady(x))?"Try my connected example accounts and save the results as one task. Label the results as examples.":"Check which of my configured services are available and tell me what needs attention.";}
function navigate(next){
 if(next!==view)clearMaskedInputs();
 if(next!==view||next!=="verification")clearDeviceEmailReview();
 if(next!=="sync")clearBitwardenSetup();
 if(next!=="verification")clearSetupDrafts();
 if(next==="verification"&&next!==view&&state)renderFactors();
 view=next;
 el("accounts-view").hidden=view!=="accounts";
 el("verification").hidden=view!=="verification";
 el("sync-view").hidden=view!=="sync";
 el("show-connect").hidden=view!=="accounts";
 el("page-title").textContent=view==="verification"?"Verification":view==="sync"?"Password sync":"Your accounts";
 el("page-intro").textContent=view==="verification"?"Connect a code source once. Your AI handles supported login challenges.":view==="sync"?"Keep approved logins current when your password manager changes.":"Keep using your AI. We handle supported sign-ins and approved reads.";
 document.querySelectorAll("[data-view]").forEach(b=>{const active=b.dataset.view===view;b.classList.toggle("active",active);if(active)b.setAttribute("aria-current","page");else b.removeAttribute("aria-current");});
}
document.querySelectorAll("[data-view]").forEach(b=>b.onclick=()=>navigate(b.dataset.view));
el("show-connect").onclick=()=>{adding=true;el("connect").hidden=false;el("connect").scrollIntoView({behavior:"smooth",block:"start"});};
el("import-nav").onclick=()=>{navigate("accounts");adding=true;el("connect").hidden=false;el("password-file").click();};
async function refresh(){
 if(locallyPaused)return;
 clearDeviceEmailReview();
 const nextState=await call("/owner/state");if(locallyPaused)return;state=nextState;
 const existing=new Set(state.accounts.map(x=>x.account));
 const previous=el("service").value;el("service").replaceChildren();
 for(const item of state.catalog.filter(x=>!existing.has(x.id))){const option=text("option",item.label);option.value=item.id;el("service").append(option);}
 if([...el("service").options].some(x=>x.value===previous))el("service").value=previous;
 permission();el("account-form").hidden=!el("service").options.length;
 const haveClients=state.principals.includes("generic");
 const tools=(state.integrations||[]).filter(x=>labels[x]);
 const automatic=tools.length>0&&tools.every(x=>state.automatic_sessions?.[x]?.enabled===true);
 el("integration-title").textContent=automatic?"Ready in every new session":"Portable skill installed";
 el("agent-status").textContent=automatic?"Ask normally in "+tools.map(x=>labels[x]).join(" or ")+". No special command needed.":"The portable integration is installed. Open a new compatible AI session to use connected accounts.";
 el("automatic-status").textContent=automatic?"Automatic":"Portable skill ready";
 el("automatic-status").classList.toggle("pending",!automatic);
 renderRecoveryHealth(state.background_recovery);
 el("connect").hidden=!haveClients||(!adding&&state.accounts.length>0);
 el("connected-section").hidden=!state.accounts.length;
 const ready=state.accounts.filter(isReady),services=state.accounts.filter(x=>!isExample(x)),examples=state.accounts.filter(isExample);
 el("account-count").textContent=services.filter(isReady).length+" ready · "+services.length+" service connections"+(examples.length?" · "+examples.filter(isReady).length+" ready / "+examples.length+" examples":"");
 el("use").hidden=!ready.length;
 el("connected").replaceChildren();
 for(const account of state.accounts){
  const card=text("div","");card.className="account";const heading=text("div","");heading.className="account-heading";heading.append(text("strong",account.label));
  const available=isReady(account);
  const status=text("span",!account.portable_ready?"Approval needed":available?(isExample(account)?"Example connected":"Connected"):"Sign-in needs attention");status.className="badge"+(available?"":" pending");heading.append(status);card.append(heading);
  if(isExample(account))card.append(text("p",account.environment==="public-example"?"Public testing website. These results do not validate access to a personal account.":"Local test connection. These results do not validate access to a personal account."));
  const operations=account.portable_ready?(account.approved_operations||[]):account.operations;
  card.append(text("p",(account.portable_ready?"Approved reads: ":"Available reads: ")+operations.map(x=>x.description).join("; ")));
  if(!available){const repair=text("a","Review access");repair.href="/manage";repair.onclick=e=>{e.preventDefault();location.href="/manage#"+capability;};card.append(repair);}
  el("connected").append(card);
 }
 el("prompts").replaceChildren();const example=text("div","");example.className="prompt";const p=text("p",prompt());const copy=text("button","Copy example");copy.type="button";copy.onclick=async()=>{try{await navigator.clipboard.writeText(p.textContent);copy.textContent="Copied";}catch{message("Select the example text to copy it.");}};example.append(p,copy);el("prompts").append(example);
 renderFactors();renderPasswordSync();navigate(view);
 if(Object.values(state.connection_jobs).some(x=>x.status==="RUNNING"))setTimeout(()=>refresh().catch(problem),1200);
}
el("service").onchange=()=>{permission();el("allow").checked=false;el("username").value="";el("password").value="";};
el("stop").onclick=async()=>{if(!confirm("Stop Account Access? Your saved connections will be kept."))return;clearMaskedInputs();clearDeviceEmailReview();clearBitwardenSetup();clearSetupDrafts();try{await call("/owner/stop",{});locallyPaused=true;clearInterval(healthTimer);message("Account Access is paused. Open the app to resume it.");el("service-status").textContent="Paused";el("recovery-health").hidden=true;document.querySelectorAll("button,input,select").forEach(x=>x.disabled=true);}catch(e){problem(e);}};
el("manage").onclick=e=>{e.preventDefault();location.href="/manage#"+capability;};
el("account-form").onsubmit=async e=>{e.preventDefault();if(locallyPaused||el("add").disabled)return;el("add").disabled=true;try{if(!el("allow").checked)throw new Error("Choose the reads you want to allow.");const payload={service:el("service").value,username:el("username").value,password:el("password").value,agents:["generic"]};el("password").value="";const request=call("/owner/add",payload);payload.password="";await request;if(locallyPaused)return;el("username").value="";el("allow").checked=false;message("Signing in. You can connect another account while this finishes.");await refresh();}catch(e){if(!locallyPaused)problem(e);}finally{el("add").disabled=locallyPaused;}};
if(capability)call("/owner/state").then(initial=>initial.local_host_actions===false?null:call("/owner/install",{})).then(refresh).then(()=>{healthTimer=setInterval(checkRecoveryHealth,5000);document.addEventListener("visibilitychange",checkRecoveryHealth);}).catch(problem);else message("Open Account Access from its launcher to unlock your setup page.");

let importPreview=null;

function renderPasswordSync(){
 if(document.querySelector('[data-bitwarden-active="true"]'))return;
 clearBitwardenSetup();
 const container=el("password-sync");container.replaceChildren();
 const note=text("div","");note.className="card";note.append(text("h2","Password file imports"),text("p","CSV and JSON imports are snapshots. Connect Bitwarden or 1Password below for ongoing updates to approved passwords. Continuous Chrome password sync is not available."));container.append(note);
 for(const link of state.password_sync||[]){
  const account=state.accounts.find(item=>item.account===link.account);const card=text("div","");card.className="account";
  card.append(text("strong",account?.label||link.account),text("p",link.provider+" · "+link.status),text("p","Checks every five minutes and before a password login. Only this approved login's password can update."));
  if(link.provider==="Bitwarden")card.append(text("p","Reconnect the Bitwarden vault below if its access changes. A replacement token cannot repair this connection."));
  else if(typeof link.generation==="string"&&/^[a-f0-9]{32}$/.test(link.generation)){
   const replace=text("button","Replace token");replace.type="button";
   const form=document.createElement("form");form.hidden=true;
   const label=text("label","Replacement read-only token");label.className="field";
   const secret=document.createElement("input");secret.type="password";secret.autocomplete="off";secret.required=true;secret.maxLength=8192;secret.setAttribute("aria-label","Replacement token for "+(account?.label||link.account));label.append(secret);
   const save=text("button","Check and replace token");save.type="submit";
   const cancel=text("button","Cancel token replacement");cancel.type="button";cancel.onclick=()=>{secret.value="";form.hidden=true;replace.hidden=false;};
   replace.onclick=()=>{form.hidden=false;replace.hidden=true;secret.focus();};
   form.append(label,text("p","Uses the same approved website and exact password-manager item. Existing access is preserved if the new token cannot be verified."),save,cancel);
   form.onsubmit=async event=>{event.preventDefault();save.disabled=true;cancel.disabled=true;const connection={token:secret.value,generation:link.generation};secret.value="";try{await call("/owner/password-sync/reconnect",{account:link.account,connection});message("Password source checked and token replaced. Website permissions are unchanged.");await refresh();}catch(error){problem(error);}finally{save.disabled=locallyPaused;cancel.disabled=locallyPaused;}};
   card.append(replace,form);
  }else card.append(text("p","A check is in progress. Reopen Password sync to refresh this connection before replacing its token."));
  const remove=text("button","Disconnect and remove saved login");remove.type="button";remove.onclick=async()=>{if(!confirm("Disconnect this source and remove its locally saved password and session? Your existing read permissions remain."))return;try{await call("/owner/password-sync/disconnect",{account:link.account});await refresh();}catch(error){problem(error);}};card.append(remove);container.append(card);
 }
 const choices=state.accounts.filter(item=>item.route==="browser"&&item.portable_ready);
 renderBitwardenSync(container,choices);
 const card=text("div","");card.className="card";card.append(text("h2","Connect 1Password"),text("p","Use a service account with read-only access to a dedicated vault, or an existing Connect server. Select the exact item for a login you already imported. Tokens stay encrypted locally and out of AI chat."));container.append(card);
 if(!choices.length){card.append(text("p","Import and approve a supported login first."));return;}
 const form=document.createElement("form");const account=document.createElement("select");account.setAttribute("aria-label","Approved account for password sync");for(const item of choices){const option=text("option",item.label);option.value=item.account;account.append(option);}form.append(account);
 const provider=document.createElement("select");provider.setAttribute("aria-label","Password source connection");provider.append(text("option","1Password service account"),text("option","1Password Connect server"));form.append(provider);
 const fields={},labels={};for(const [key,title] of [["endpoint","Connect server HTTPS address"],["vault","Vault ID"],["item","Login item ID"],["token","Service-account token for a read-only vault"]]){const label=text("label",title);label.className="field";const input=document.createElement("input");input.type=key==="token"?"password":"text";input.required=true;input.setAttribute("aria-label",title);input.autocomplete="off";label.append(input);fields[key]=input;labels[key]=label;form.append(label);}
 provider.onchange=()=>{const service=provider.selectedIndex===0;labels.endpoint.hidden=service;fields.endpoint.disabled=service;fields.endpoint.value="";fields.token.value="";fields.token.setAttribute("aria-label",service?"Service-account token for a read-only vault":"Read-only Connect token");labels.token.firstChild.textContent=fields.token.getAttribute("aria-label");};provider.onchange();
 const save=text("button","Connect automatic updates");save.type="submit";form.append(save);form.onsubmit=async event=>{event.preventDefault();save.disabled=true;const connection={vault:fields.vault.value,item:fields.item.value,token:fields.token.value};if(provider.selectedIndex===0)connection.provider="onepassword-service-account";else connection.endpoint=fields.endpoint.value;fields.token.value="";try{await call("/owner/password-sync",{account:account.value,connection});message("Password source connected. Approved passwords can now update automatically.");await refresh();}catch(error){problem(error);}finally{save.disabled=locallyPaused;}};card.append(form);
}
function renderBitwardenSync(container,choices){
 const hex=value=>typeof value==="string"&&value.length===32&&/^[a-f0-9]{32}$/.test(value);
 const uuid=value=>typeof value==="string"&&value.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
 const connections=(state.bitwarden_connections||[]).filter(connection=>hex(connection.id)&&hex(connection.generation));
 for(const connection of connections){const card=text("div","");card.className="account";const status=connection.status||"CONNECTED";card.append(text("strong","Bitwarden · "+connection.email),text("p",status==="CONNECTED"?"Connected":status==="RETRYABLE"?"Temporarily unavailable":"Reconnect needed"),text("p",(connection.region==="eu"?"Europe":"United States")+" server. This encrypted connection is separate from your other Bitwarden apps; locking another app does not disconnect it."));const remove=text("button","Disconnect Bitwarden vault");remove.type="button";remove.onclick=async()=>{if(!confirm("Remove this Bitwarden connection and its locally saved linked passwords and sessions? Approved website read permissions remain."))return;try{await call("/owner/bitwarden/disconnect",{id:connection.id,generation:connection.generation});await refresh();}catch(error){bitwardenProblem(error);}};card.append(remove);container.append(card);}
 const card=text("div","");card.className="card";card.setAttribute("aria-label","Bitwarden live sync");container.append(card);
 if(state.bitwarden_available!==true){card.append(text("h2","Bitwarden live sync"),text("p","Update or repair Account Access to install its protected Bitwarden component. File import still works; live setup becomes available after repair."));return;}
 card.append(text("h2","Connect Bitwarden once"),text("p","Keep selected, already-approved login passwords current automatically. Your master password is used to unlock this setup only and is never saved."));
 const open=text("button","Connect Bitwarden");open.type="button";const form=document.createElement("form");form.hidden=true;form.setAttribute("aria-label","One-time Bitwarden connection");
 form.append(text("p","In the Bitwarden web vault, open Settings → Security → Keys, then View API key. Choose the same server region you use in Bitwarden."));const help=text("a","Bitwarden setup instructions");help.href="https://bitwarden.com/help/personal-api-key/";help.target="_blank";help.rel="noopener noreferrer";form.append(help);
 const region=document.createElement("select");region.setAttribute("aria-label","Bitwarden server region");for(const [value,title] of [["us","United States · bitwarden.com"],["eu","Europe · bitwarden.eu"]]){const option=text("option",title);option.value=value;region.append(option);}form.append(region);
 const fields={};for(const [key,title,limit] of [["client_id","Personal API client ID",41],["client_secret","Personal API client secret",8192],["master_password","Bitwarden master password",4096]]){const label=text("label",title);label.className="field";const field=document.createElement("input");field.type="password";field.autocomplete="off";field.required=true;field.maxLength=limit;field.setAttribute("aria-label",title);field.dataset.bitwardenSecret="";label.append(field);form.append(label);fields[key]=field;}
 form.append(text("p","This Bitwarden session can decrypt your whole vault. Account Access stores it encrypted locally and fetches only exact items linked to approved logins. Disconnecting removes this connection and its saved linked passwords and sessions. No vault list, key or password is sent to your AI."));
 const consent=document.createElement("input");consent.type="checkbox";consent.required=true;consent.dataset.bitwardenConsent="";consent.setAttribute("aria-label","Allow local Bitwarden vault decryption");const consentLabel=text("label","Allow Account Access to decrypt my Bitwarden vault locally");consentLabel.prepend(consent);form.append(consentLabel);
 const save=text("button","Connect Bitwarden vault");save.type="submit";const cancel=text("button","Cancel Bitwarden setup");cancel.type="button";cancel.onclick=()=>{clearBitwardenSetup();form.hidden=true;open.hidden=false;};open.onclick=()=>{clearBitwardenSetup();form.dataset.bitwardenActive="true";form.hidden=false;open.hidden=true;fields.client_id.focus();};form.append(save,cancel);
 form.onsubmit=async event=>{event.preventDefault();if(!consent.checked){message(friendly.bitwarden_vault_consent_required);return;}const body={region:region.value,client_id:fields.client_id.value,client_secret:fields.client_secret.value,master_password:fields.master_password.value,consent_vault_access:true};clearBitwardenSetup();save.disabled=true;cancel.disabled=true;message("Connecting Bitwarden. This can take up to a minute; your master password will not be saved.");try{await call("/owner/bitwarden/connect",body);await refresh();message("Bitwarden connected. Choose an approved login below for automatic password updates.");}catch(error){bitwardenProblem(error);}finally{save.disabled=locallyPaused;cancel.disabled=locallyPaused;}};
 card.append(open,form);
 const connectedVaults=connections.filter(connection=>!connection.status||connection.status==="CONNECTED");
 if(!connectedVaults.length||!choices.length){card.append(text("p","Import and approve a supported login, then select it after connecting Bitwarden."));return;}
 const linking=document.createElement("form");linking.setAttribute("aria-label","Bitwarden approved login sync");linking.append(text("h3","Keep an approved login current"));
 const account=document.createElement("select");account.setAttribute("aria-label","Approved account for Bitwarden sync");for(const choice of choices){const option=text("option",choice.label);option.value=choice.account;account.append(option);}linking.append(account);
 const vault=document.createElement("select");vault.setAttribute("aria-label","Connected Bitwarden vault");for(const connection of connectedVaults){const option=text("option",connection.email+" · "+connection.region);option.value=connection.id;vault.append(option);}linking.append(vault);
 const note=text("p","");const itemLabel=text("label","Bitwarden login item ID (advanced)");itemLabel.className="field";const item=document.createElement("input");item.type="text";item.autocomplete="off";item.maxLength=36;item.setAttribute("aria-label","Bitwarden login item ID (advanced)");itemLabel.append(item);linking.append(note,itemLabel);
 account.onchange=()=>{const suggestion=choices.find(choice=>choice.account===account.value)?.password_sync_suggestion;const imported=suggestion?.provider==="bitwarden"&&uuid(suggestion.item);item.value=imported?suggestion.item:"";item.disabled=imported;item.required=!imported;itemLabel.hidden=imported;note.textContent=imported?"Uses the exact Bitwarden login selected during password import. Only its password can update.":"Advanced: enter this login's exact Bitwarden item ID. Its website and username are checked before linking.";};account.onchange();
 const link=text("button","Connect Bitwarden automatic updates");link.type="submit";linking.append(link);linking.onsubmit=async event=>{event.preventDefault();const connection=connections.find(candidate=>candidate.id===vault.value);if(!connection||!uuid(item.value)){message("Choose the current Bitwarden connection and this login's exact item.");return;}link.disabled=true;try{await call("/owner/password-sync",{account:account.value,connection:{provider:"bitwarden",connection:connection.id,connection_generation:connection.generation,item:item.value}});await refresh();message("Bitwarden password updates connected for this approved login.");}catch(error){bitwardenProblem(error);}finally{link.disabled=locallyPaused;}};card.append(linking);
}
el("import-passwords").onclick=()=>{adding=true;el("password-file").click();};
el("password-file").onchange=async()=>{
 const file=el("password-file").files[0]; if(!file)return;
 importPreview=null;el("import-review").replaceChildren();el("import-review").hidden=true;
 try {if(file.size>4000000)throw new Error("password_file_too_large");let contents;try{contents=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());}catch{throw new Error("invalid_password_export");}importPreview=await call("/owner/import/preview",{csv:contents});
 const review=el("import-review");review.replaceChildren();review.hidden=false;
 review.append(text("p","Select up to 32 logins and approve their reads. Selected saved logins will be replaced. Passwords are hidden."));
 const inputs=[];const importAuth=document.createElement("input");importAuth.type="checkbox";const authLabel=text("label","Also enroll included authenticator keys for supported login recovery");authLabel.prepend(importAuth);if(importPreview.rows.some(x=>x.has_authenticator))review.append(authLabel);
 for(const row of importPreview.rows.filter(x=>x.matches.length).slice(0,200)){
  const label=text("label",row.username+" · "+row.website);const check=document.createElement("input");check.type="checkbox";label.prepend(check);
  const select=document.createElement("select");for(const match of row.matches){const option=text("option",match.label+" — Allow: "+match.operations.map(x=>x.description).join("; "));option.value=match.id;select.append(option);}
  review.append(label,select);inputs.push({row,check,select});
 }
 review.append(text("p",importPreview.unsupported+" unsupported logins will not be saved. Delete the plaintext export after importing; this web page cannot delete your file."));
 const submit=text("button","Import selected accounts");submit.type="button";submit.onclick=async()=>{try{
 const selections=inputs.filter(x=>x.check.checked).map(x=>({row:x.row.id,account:x.select.value,operations:x.row.matches.find(m=>m.id===x.select.value).operations.map(o=>o.name),include_authenticator:importAuth.checked&&x.row.has_authenticator&&x.row.matches.find(m=>m.id===x.select.value).authenticator_supported}));
 await call("/owner/import/apply",{id:importPreview.id,selections});review.replaceChildren();review.hidden=true;importPreview=null;el("password-file").value="";message("Logins imported and encrypted. Enroll required verification below.");await refresh();
 }catch(e){problem(e);}};review.append(submit);
 }catch(e){el("password-file").value="";problem(e);}
};
function renderMailboxes(container){
 const mailboxDrafts=new Set((state.mailboxes||[]).map(mailbox=>"mailbox-edit:"+mailbox.id));for(const key of setupDrafts.keys())if(key.startsWith("mailbox-edit:")&&!mailboxDrafts.has(key))clearSetupDraft(key);
 const googleConnections=state.mailbox_oauth||[];
 for(const mailbox of googleConnections){
  const card=text("div","");card.className="account";card.setAttribute("aria-label","Google mailbox connection");const reusable=mailbox.reusable_mailbox;const recipients=[...new Set((mailbox.sources||[]).map(source=>source.recipient))];const address=reusable?.recipient||recipients.join(", ");card.append(text("strong",address?"Gmail · "+address:"Gmail"));
  card.append(text("p","Connect in Google's browser page. Google grants mailbox read access; Account Access uses matching login messages for your configured websites. Website permissions stay the same."));
  if(mailbox.environment==="controlled-demo")card.append(text("p","Controlled provider fixture. This is not a real Gmail connection."));
  const needsAttention=mailbox.connection_state==="needs_attention"||(mailbox.connected&&mailbox.renewable_access_saved!==true);
  const connected=mailbox.connected&&mailbox.renewable_access_saved===true&&!needsAttention;
  const checked=connected&&mailbox.mailbox_identity_verified===true&&!!reusable;
  if(needsAttention)card.append(text("p",mailbox.reason==="mailbox_scope_not_allowed"?friendly.mailbox_scope_not_allowed:mailbox.reason==="refresh_outcome_uncertain"?"Google access renewal was interrupted. Reconnect once to restore automatic email-code access.":"The saved Google connection needs attention. Reconnect once to restore renewable email-code access."));
  if(!mailbox.publisher_configured)card.append(text("p","The publisher must finish configuring its Google application before browser sign-in is available. Never enter your normal Google password here."));
  else if(state.local_host_actions===false)card.append(text("p","Open Verification in the Account Access desktop app to connect Google in your browser."));
  else{const connect=text("button",connected||needsAttention?"Reconnect with Google":"Connect with Google");connect.type="button";connect.onclick=async()=>{connect.disabled=true;try{await call("/owner/mailbox/oauth/connect",{account:mailbox.account,fingerprint:mailbox.fingerprint});message("Choose the approved Google account in your browser. After consent, enable or check the website's email verification to confirm its mailbox address.");await refresh();}catch(e){problem(e);}finally{connect.disabled=locallyPaused;}};card.append(connect);}
  if(connected){
   card.append(text("p",checked?"Google mailbox checked. Choose it for a supported website's email verification without an app password. Code delivery is checked during sign-in.":"Google access is saved. Check its address to use this mailbox for supported website verification; no app password or repeated consent is needed."));
   const check=text("button","Check Google connection");check.type="button";check.onclick=async()=>{if(check.disabled)return;check.disabled=true;try{const result=await call("/owner/mailbox/oauth/check",{account:mailbox.account,fingerprint:mailbox.fingerprint});if(result.status!=="VERIFIED")throw new Error("mailbox_connection_not_completed");message("Google mailbox checked. Choose it for a supported website's email verification. Code delivery is checked during sign-in.");await refresh();}catch(error){problem(error);}finally{check.disabled=locallyPaused;}};card.append(check);
  }container.append(card);
 }
 if(!googleConnections.length)container.append(text("p","Sign in with Google needs the publisher's registered Gmail connection. This preview does not include one. Gmail app passwords are available only for accounts where Google permits them."));
 for(const mailbox of state.mailboxes||[]){
  const card=text("div","");card.className="account";card.append(text("strong",mailbox.label+" · "+mailbox.username));
  const checked=mailbox.connection_check?.status==="VERIFIED";card.append(text("p",checked?"Mailbox connection checked. Website code delivery is checked separately.":"Setup saved. Check the address and application password."));
  const check=text("button","Check connection");check.type="button";check.onclick=async()=>{try{await call("/owner/mailbox/check",{id:mailbox.id});await refresh();}catch(e){problem(e);}};card.append(check);
  const key="mailbox-edit:"+mailbox.id,previous=setupDrafts.get(key);const valid=/^[a-f0-9]{64}$/.test(mailbox.setup_revision||"");
  if(previous?.active&&valid&&previous.revision===mailbox.setup_revision)card.append(previous.card);
  else{
   if(previous)clearSetupDraft(key);const edit=document.createElement("form"),password=document.createElement("input");password.type="password";password.required=true;password.autocomplete="off";password.maxLength=4096;password.placeholder="New mailbox application password";password.setAttribute("aria-label",password.placeholder);
   const draft={card:edit,revision:mailbox.setup_revision,active:false,secrets:[password]};setupDrafts.set(key,draft);password.oninput=()=>{if(!setupOperations.has(key)&&edit.isConnected&&view==="verification"&&!locallyPaused){draft.active=!!password.value;setupDrafts.set(key,draft);}};
   const update=text("button","Update app password");update.type="submit";const cancel=text("button","Cancel mailbox password change");cancel.type="button";cancel.onclick=()=>{if(setupOperations.has(key))return;clearSetupDraft(key);renderFactors();};password.disabled=update.disabled=cancel.disabled=!valid||setupOperations.has(key);edit.append(password,update,cancel);
   edit.onsubmit=async event=>{event.preventDefault();if(locallyPaused||setupOperations.has(key)||setupDrafts.get(key)!==draft||update.disabled)return;const operation={cancelled:false,epoch:setupEpoch};setupOperations.set(key,operation);draft.active=true;password.disabled=update.disabled=cancel.disabled=true;const payload={id:mailbox.id,password:password.value};password.value="";try{const request=call("/owner/mailbox/password",payload);payload.password="";await request;}catch(error){if(!operation.cancelled&&operation.epoch===setupEpoch&&!locallyPaused)problem(error);}finally{password.value="";draft.active=false;if(setupOperations.get(key)===operation)setupOperations.delete(key);if(!locallyPaused){password.disabled=update.disabled=cancel.disabled=locallyPaused;await refresh().catch(problem);}}};card.append(edit);
  }
  const disconnect=text("button","Disconnect mailbox");disconnect.type="button";disconnect.onclick=async()=>{if(!confirm("Remove the saved mailbox password? Websites using it will pause when they next need an email code."))return;clearSetupDraft(key);try{await call("/owner/mailbox/remove",{id:mailbox.id});await refresh();}catch(e){problem(e);}};card.append(disconnect);container.append(card);
 }
 const newKey="mailbox-new",previousNew=setupDrafts.get(newKey);if(previousNew?.active){container.append(previousNew.card);return;}
 const details=document.createElement("details");details.append(text("summary","Connect Gmail or email"));const form=document.createElement("form");const provider=document.createElement("select");provider.setAttribute("aria-label","Email provider");for(const label of ["Gmail","Other email · TLS IMAP"])provider.append(text("option",label));form.append(provider);const fields={};
 for(const [name,label] of [["username","Email address"],["password","Application password"],["host","IMAP server"],["port","TLS port"]]){const input=document.createElement("input");input.type=name==="password"?"password":name==="port"?"number":"text";input.required=true;input.placeholder=label;input.setAttribute("aria-label",label);fields[name]=input;form.append(input);}
 const newDraft={card:details,active:false,secrets:[fields.password]};setupDrafts.set(newKey,newDraft);const activate=()=>{if(details.isConnected&&view==="verification"&&!locallyPaused){newDraft.active=true;setupDrafts.set(newKey,newDraft);}};Object.values(fields).forEach(field=>field.oninput=activate);details.ontoggle=()=>{if(details.open)activate();else if(!setupOperations.has(newKey)){clearSetupDraft(newKey);}};
 provider.onchange=()=>{const gmail=provider.selectedIndex===0;fields.host.value=gmail?"imap.gmail.com":"";fields.port.value="993";fields.host.readOnly=fields.port.readOnly=gmail;fields.host.hidden=fields.port.hidden=gmail;if(details.isConnected)activate();};provider.onchange();
 details.append(text("p","For Gmail, create a Google app password for Account Access with 2-Step Verification enabled. If Google does not offer app passwords, use the configured Google browser connection above."));const google=text("a","Open Google App passwords");google.href="https://myaccount.google.com/apppasswords";google.target="_blank";google.rel="noreferrer";details.append(google);const save=text("button","Connect mailbox");save.type="submit";const cancel=text("button","Cancel mailbox setup");cancel.type="button";cancel.onclick=()=>{if(setupOperations.has(newKey))return;clearSetupDraft(newKey);renderFactors();};form.append(save,cancel);
 const controls=[save,cancel,provider,...Object.values(fields)];controls.forEach(control=>control.disabled=setupOperations.has(newKey));
 form.onsubmit=async event=>{
  event.preventDefault();if(locallyPaused||setupOperations.has(newKey)||setupDrafts.get(newKey)!==newDraft||save.disabled)return;
  const operation={cancelled:false,epoch:setupEpoch};setupOperations.set(newKey,operation);newDraft.active=true;controls.forEach(control=>control.disabled=true);
  const current=()=>!operation.cancelled&&operation.epoch===setupEpoch&&!locallyPaused&&view==="verification"&&setupDrafts.get(newKey)===newDraft;
  let retryDraft=false;
  try{
   const payload=Object.fromEntries(Object.entries(fields).map(([key,input])=>[key,input.value]));payload.port=Number(payload.port);payload.label=provider.selectedIndex===0?"Gmail":"Email";
   fields.password.value="";const request=call("/owner/mailbox/connect",payload);payload.password="";await request;
   if(current())message("Mailbox setup saved. Its connection result is shown below; no website sign-in was started.");
  }catch(error){if(current()){retryDraft=true;problem(error);}}
  finally{
   fields.password.value="";newDraft.active=retryDraft&&current();
   if(setupOperations.get(newKey)===operation)setupOperations.delete(newKey);
   if(!locallyPaused){controls.forEach(control=>control.disabled=locallyPaused);await refresh().catch(problem);}
  }
 };details.append(form,text("p","Your app password grants mailbox access and is encrypted locally. Account Access uses read-only checks and matching login messages for approved sign-ins. Mailbox checks fetch no messages and start no website login."));container.append(details);
}
function renderDeviceEmailSetups(container){
 for(const setup of state.device_email_setups||[]){
  const card=text("div","");card.className="account";card.setAttribute("aria-label",setup.label+" device confirmation email");container.append(card);
  card.append(text("strong",setup.label+" · Device confirmation email"));
  const configured=setup.configured??setup.connected;
  const badge=text("span",setup.connected?"Setup saved · delivery unverified":configured?"Email connection needs attention":"One-time setup");badge.className="badge pending";card.append(badge);
  if(configured){
   if(setup.connected)card.append(text("p","Fresh matching PyPI device-confirmation emails are handled locally during sign-in. Saving setup does not verify email delivery."));
   const remove=text("button","Disconnect device email");remove.type="button";remove.onclick=async()=>{if(remove.disabled)return;remove.disabled=true;clearDeviceEmailReview();try{await call("/owner/device-email/remove",{account:setup.account,fingerprint:setup.fingerprint});message("Device email disconnected. Your existing approved reads are retained.");await refresh();}catch(error){deviceEmailProblem(error);remove.disabled=locallyPaused;}};card.append(remove);if(setup.connected)continue;
  }
  card.append(text("p","Use an email mailbox you already connected and checked. No password or login code needs to be entered again."));
  if(!setup.mailboxes?.length){
   card.append(text("p","Connect and check an email mailbox first. A checked Google connection or TLS IMAP mailbox can be used without entering its password again."));
   const connect=text("button","Connect a mailbox");connect.type="button";connect.onclick=()=>{const form=container.querySelector("details");if(form){form.open=true;form.scrollIntoView({block:"start"});}};card.append(connect);continue;
  }
  const menu=document.createElement("select");menu.setAttribute("aria-label","Connected mailbox for "+setup.label+" device emails");
  for(const mailbox of setup.mailboxes){const option=text("option",mailbox.label+" · "+mailbox.recipient);option.value=mailbox.id;menu.append(option);}card.append(menu);
  const preview=text("button","Review email connection");preview.type="button";card.append(preview);
  preview.onclick=async()=>{
   if(preview.disabled)return;clearDeviceEmailReview();preview.disabled=true;deviceEmailPreviewButton=preview;const epoch=deviceEmailEpoch;
   try{
    const review=await call("/owner/device-email/preview",{account:setup.account,fingerprint:setup.fingerprint,mailbox:menu.value});
    if(epoch!==deviceEmailEpoch||view!=="verification"||locallyPaused){if(review.id)call("/owner/device-email/discard",{id:review.id}).catch(()=>{});return;}
    if(typeof review.id!=="string"||!/^[a-f0-9]{32}$/.test(review.id)||review.account!==setup.account||typeof review.expires!=="number"||review.expires*1000<=Date.now()||typeof review.recipient!=="string"||typeof review.mailbox_label!=="string"||!Array.isArray(review.operations)){if(review.id)call("/owner/device-email/discard",{id:review.id}).catch(()=>{});throw new Error("device_email_setup_expired");}
    deviceEmailReview=review;
    const panel=text("div","");panel.className="card";panel.setAttribute("role","region");panel.setAttribute("aria-label","Review device email connection");deviceEmailReviewNode=panel;
    panel.append(text("h3","Confirm device email"),text("p",review.mailbox_label+" · "+review.recipient),text("p","Account Access reads only fresh matching PyPI sign-in emails locally during a supported login. No password, code or link is sent to your AI. Your existing approved reads are retained."));
    for(const operation of review.operations){if(typeof operation.description==="string")panel.append(text("p","Approved read: "+operation.description));}
    panel.append(text("p","Saving this setup does not verify delivery or sign in to PyPI."));
    const apply=text("button","Confirm email connection");apply.type="button";
    const cancel=text("button","Cancel email connection");cancel.type="button";cancel.onclick=()=>{clearDeviceEmailReview();preview.disabled=locallyPaused;};
    apply.onclick=async()=>{
     if(apply.disabled||deviceEmailReview!==review)return;apply.disabled=true;cancel.disabled=true;
     if(review.expires*1000<=Date.now()){clearDeviceEmailReview();deviceEmailProblem(new Error("device_email_setup_expired"));preview.disabled=locallyPaused;return;}
     deviceEmailReview=null;deviceEmailReviewNode=null;panel.remove();
     try{await call("/owner/device-email/apply",{id:review.id});message("Device email setup saved. Delivery is checked during an actual sign-in; approved reads are retained.");await refresh();}
     catch(error){deviceEmailProblem(error);await refresh().catch(()=>{});}
    };
    panel.append(apply,cancel);card.append(panel);
   }catch(error){deviceEmailProblem(error);preview.disabled=locallyPaused;}
  };
 }
}
function renderGoogleMessages(container){
 const sources=(state.code_sources||[]).filter(source=>source.kind==="google_messages");
 if(!sources.length&&!state.sms_setups?.length){googleMessagesSetup=null;return;}
 const context=JSON.stringify({sources:sources.map(source=>[source.id,!!source.enrolled,source.accounts.map(id=>[id,state.accounts.find(account=>account.account===id)?.label||id])]),sms_setups:(state.sms_setups||[]).map(setup=>[setup.account,setup.fingerprint])});
 if(state.local_host_actions!==false&&googleMessagesSetup?.active&&googleMessagesSetup.context===context){container.append(googleMessagesSetup.card);return;}
 googleMessagesSetup=null;
 const card=text("div","");card.className="account";card.setAttribute("aria-label","Android SMS · Google Messages");
 card.append(text("h2","Android SMS · Google Messages"),text("p","Use the Google Messages browser tab already paired to your phone for SMS login codes. This connection supports reviewed GitHub sign-ins."));
 const saved=sources.some(source=>source.enrolled);
 const badge=text("span",saved?"Setup saved · delivery unverified":"One-time browser connection");badge.className="badge pending";card.append(badge);
 card.append(text("p","Chrome separately asks for access to messages.google.com. During an active approved GitHub sign-in, the helper passes only fresh matching login codes locally. GitHub rotates sender numbers, so sender identity is not independently verified. Your AI receives no codes or message contents."));
 for(const source of sources){
  const names=source.accounts.map(id=>state.accounts.find(account=>account.account===id)?.label||id).join(", ");
  card.append(text("p",names+" · "+(source.enrolled?"SMS setup saved. Code delivery is checked during sign-in.":"SMS access is not enabled.")));
  if(source.enrolled){const disable=text("button","Disable Google Messages SMS for "+names);disable.type="button";disable.onclick=async()=>{if(disable.disabled)return;disable.disabled=true;try{await call("/owner/source/revoke",{source:source.id});message("Google Messages SMS disabled for this connection.");await refresh();}catch(error){problem(error);disable.disabled=locallyPaused;}};card.append(disable);}
 }
 if(state.local_host_actions===false){card.append(text("p","Open Verification in the Account Access desktop app and choose Set up Google Messages. Browser setup must be prepared by the local desktop app."));container.append(card);return;}
 const setup={card,context,active:false,pending:false};googleMessagesSetup=setup;
 const review=document.createElement("form");review.hidden=true;review.setAttribute("aria-label","Review Google Messages preparation");
 review.append(text("h3","Prepare the SMS browser connection"),text("p","This installs the local bridge for the Account Access Chrome extension. Preparing it grants no Chrome site permission and does not confirm SMS delivery."));
 const consent=document.createElement("input");consent.type="checkbox";consent.required=true;const label=text("label","Allow Account Access to prepare the local Google Messages bridge");label.prepend(consent);review.append(label);
 const prepare=text("button","Prepare browser connection");prepare.type="submit";prepare.disabled=true;consent.onchange=()=>prepare.disabled=!consent.checked;
 const cancel=text("button","Cancel browser preparation");cancel.type="button";cancel.onclick=()=>{if(setup.pending)return;setup.active=false;consent.checked=false;prepare.disabled=true;review.hidden=true;start.hidden=false;};
 const start=text("button","Set up Google Messages");start.type="button";start.onclick=()=>{if(setup.pending||locallyPaused)return;setup.active=true;consent.checked=false;prepare.disabled=true;review.hidden=false;start.hidden=true;};
 const instructions=text("div","");instructions.setAttribute("role","region");instructions.setAttribute("aria-label","Add the SMS browser connection");instructions.hidden=true;
 function showPreparation(result){
  setup.active=false;review.hidden=true;start.hidden=true;instructions.hidden=false;instructions.replaceChildren();badge.textContent="Browser bridge prepared · delivery unverified";
  instructions.append(text("h3","Add the SMS browser connection"),text("p","The local bridge is prepared. Finish the separate Chrome extension setup to enable SMS access. No website sign-in has started."));
  const steps=document.createElement("ol");
  for(const step of ["In Chrome, open Extensions → Manage Extensions and turn on Developer mode.","Choose Load unpacked, then select the GoogleMessagesExtension folder shown below.","Open Account Access — Browser Connections in Chrome, choose your reviewed GitHub account, and select Connect GitHub login texts. Review Chrome's site permission request.","Keep one Google Messages conversations tab open and paired to your phone. Fresh code delivery is checked during a supported sign-in."])steps.append(text("li",step));
  instructions.append(steps,text("p","Folder to select in Chrome:"),text("p",result.extension_path));
  const messages=text("a","Open Google Messages");messages.href="https://messages.google.com/web/conversations";messages.target="_blank";messages.rel="noreferrer";instructions.append(messages);
 }
 review.onsubmit=async event=>{event.preventDefault();if(setup.pending||googleMessagesSetup!==setup||locallyPaused||prepare.disabled||!consent.checked)return;setup.active=true;setup.pending=true;prepare.disabled=true;cancel.disabled=true;consent.disabled=true;try{const result=await call("/owner/google-messages/prepare",{});if(googleMessagesSetup!==setup||locallyPaused)return;if(result.status!=="PREPARED"||typeof result.extension_path!=="string"||!result.extension_path)throw new Error("browser_connection_not_prepared");googleMessagesPreparation=result;showPreparation(result);message("Browser bridge prepared. Complete the Chrome steps below; SMS delivery is still unverified.");}catch(error){if(googleMessagesSetup===setup&&!locallyPaused)message("The browser connection could not be prepared. Open Verification in the Account Access desktop app to try again.");}finally{setup.pending=false;consent.checked=false;consent.disabled=locallyPaused;cancel.disabled=locallyPaused;prepare.disabled=true;}};
 review.append(prepare,cancel);card.append(start,review,instructions);if(googleMessagesPreparation)showPreparation(googleMessagesPreparation);container.append(card);
}
function renderAuthenticator(container,source){
 const key="totp:"+source.id,previous=setupDrafts.get(key),pending=setupOperations.get(key);
 const valid=/^[a-f0-9]{64}$/.test(source.setup_context||"")&&/^[a-f0-9]{64}$/.test(source.setup_revision||"");
 if(pending&&pending.context!==source.setup_context)pending.cancelled=true;
 if(previous?.active&&valid&&previous.context===source.setup_context&&previous.revision===source.setup_revision){container.append(previous.card);return;}
 if(previous)clearSetupDraft(key,!valid||previous.context!==source.setup_context);
 const names=source.accounts.map(id=>state.accounts.find(account=>account.account===id)?.label||id).join(", ");
 const card=text("div","");card.className="account";card.dataset.authenticatorSource=source.id;card.setAttribute("aria-label","Authenticator · "+names);
 card.append(text("strong","Authenticator"),text("p",names));const badge=text("span",source.enrolled?"Setup saved":"One-time setup");badge.className="badge"+(source.enrolled?"":" pending");card.append(badge);
 card.append(text("p","Use the website's original setup key or otpauth link, rather than a current six-digit code. For Google Authenticator on your phone, open Verification in the Account Access desktop app to import its complete Transfer codes export."),text("p","This copies the authenticator key to this computer for unattended sign-in. It stays encrypted locally and out of AI chat. Your phone keeps generating codes; push, passkey or fingerprint approval still needs you."));
 const form=document.createElement("form"),seed=document.createElement("input");seed.type="password";seed.required=true;seed.maxLength=2048;seed.autocomplete="off";seed.placeholder="Authenticator setup key or otpauth link";seed.setAttribute("aria-label",seed.placeholder);
 const draft={card,context:source.setup_context,revision:source.setup_revision,active:false,secrets:[seed]};setupDrafts.set(key,draft);
 seed.oninput=()=>{if(!card.isConnected||view!=="verification"||locallyPaused||setupOperations.has(key))return;draft.active=!!seed.value;setupDrafts.set(key,draft);};
 const submit=text("button",source.enrolled?"Update verification":"Enable verification");submit.type="submit";
 const cancel=text("button","Cancel authenticator setup");cancel.type="button";cancel.onclick=()=>{if(setupOperations.has(key))return;clearSetupDraft(key);renderFactors();};
 seed.disabled=submit.disabled=cancel.disabled=!valid||!!pending;
 form.append(seed,submit,cancel);card.append(form);
 form.onsubmit=async event=>{
  event.preventDefault();if(locallyPaused||view!=="verification"||setupOperations.has(key)||setupDrafts.get(key)!==draft||submit.disabled)return;
  const operation={context:draft.context,epoch:setupEpoch,cancelled:false};setupOperations.set(key,operation);draft.active=true;seed.disabled=submit.disabled=cancel.disabled=true;
  const credential={seed:seed.value};seed.value="";
  const current=()=>!operation.cancelled&&operation.epoch===setupEpoch&&!locallyPaused&&view==="verification";
  try{
   const request=call("/owner/source",{source:source.id,credential});credential.seed="";const result=await request;if(!current())return;
   const latest=await call("/owner/state");if(!current())return;const now=latest.code_sources.find(item=>item.id===source.id);
   if(result.status!=="ENROLLED"||result.source!==source.id||result.kind!=="totp"||result.setup_context!==operation.context||now?.setup_context!==operation.context||now?.setup_revision!==result.setup_revision){message("This authenticator connection changed. Review its current setup in Verification.");return;}
   for(const account of source.accounts){if(!current())return;const connected=latest.accounts.find(item=>item.account===account);if(!connected?.challenges?.some(challenge=>["captcha","passkey","device","admin","action","recovery","unknown"].includes(challenge.kind)))await call("/owner/verify",{account});}
   if(current())message("Authenticator saved locally. Checking supported website sign-ins; your AI receives no key or code.");
  }catch(error){if(current())problem(error);}finally{seed.value="";draft.active=false;if(setupOperations.get(key)===operation)setupOperations.delete(key);if(!locallyPaused){seed.disabled=submit.disabled=cancel.disabled=locallyPaused;await refresh().catch(error=>{if(current())problem(error);});}}
 };
 if(source.enrolled){const disable=text("button","Disable verification");disable.type="button";disable.onclick=async()=>{if(disable.disabled)return;clearSetupDraft(key);disable.disabled=true;try{await call("/owner/source/revoke",{source:source.id});await refresh();}catch(error){problem(error);disable.disabled=locallyPaused;}};card.append(disable);}
 container.append(card);
}
function renderFactors(){
 const container=el("factors");container.replaceChildren();
 const authenticators=new Set(state.code_sources.filter(source=>source.kind==="totp").map(source=>"totp:"+source.id));for(const key of setupDrafts.keys())if(key.startsWith("totp:")&&!authenticators.has(key))clearSetupDraft(key);
 renderMailboxes(container);
 renderDeviceEmailSetups(container);
 renderGoogleMessages(container);
 for(const source of state.code_sources.filter(item=>item.message_purpose!=="pypi-device-confirmation"&&item.kind!=="google_messages")){
  if(source.kind==="totp"){renderAuthenticator(container,source);continue;}
  const card=document.createElement("div");card.className="account";card.dataset.verificationSource=source.id;const kind={totp:"Authenticator",imap:"Email",gmail:"Gmail",twilio:"SMS gateway",mac_messages:"iPhone Messages",phone_relay:"Android phone"}[source.kind]||"Verification";card.append(text("strong",kind));card.append(text("p",source.accounts.map(id=>state.accounts.find(x=>x.account===id)?.label||id).join(", ")));const email=["imap","gmail"].includes(source.kind);const checked=source.connection_check?.status==="VERIFIED";const status=text("span",source.enrolled?(email&&checked?"Mailbox connection checked":"Setup saved"):"One-time setup");status.className="badge"+(source.enrolled?"":" pending");card.append(status);
  if(email&&source.enrolled){card.append(text("p",checked?"Email access passed its last check. Website code delivery is still a separate check.":"Saving these details does not verify email access or code delivery."));const check=text("button","Check email connection");check.type="button";check.onclick=async()=>{check.disabled=true;try{await call("/owner/source/check",{source:source.id});message("Mailbox connection checked. No messages fetched or website sign-in started.");await refresh();}catch(e){problem(e);}finally{check.disabled=locallyPaused;}};card.append(check);}
  const form=document.createElement("form");const fields={};
  const names=source.kind==="totp"?["seed"]:source.kind==="imap"?(source.mailbox_account?["username"]:["username","password"]):source.kind==="twilio"?["sid","auth_token"]:[];
  let mailboxMenu=null;if(source.kind==="imap"&&!source.mailbox_account){const matching=(state.mailboxes||[]).filter(x=>x.host.toLowerCase()===source.mail_server?.toLowerCase()&&x.port===source.mail_port&&x.username.toLowerCase()===source.recipient?.toLowerCase());if(matching.length){mailboxMenu=document.createElement("select");mailboxMenu.setAttribute("aria-label","Use a connected mailbox");mailboxMenu.append(text("option","Enter mailbox details"));mailboxMenu.firstChild.value="";for(const mailbox of matching){const option=text("option",mailbox.username);option.value=mailbox.id;mailboxMenu.append(option);}mailboxMenu.value=source.linked_mailbox||"";form.append(mailboxMenu);}}
  if(source.kind==="gmail"&&source.mailbox_options?.length){
   mailboxMenu=document.createElement("select");mailboxMenu.setAttribute("aria-label","Use a connected Gmail mailbox");
   for(const mailbox of source.mailbox_options){if(mailbox.kind!=="gmail")continue;const option=text("option",`${mailbox.label} · ${mailbox.recipient}`);option.value=mailbox.id;mailboxMenu.append(option);}
   mailboxMenu.value=source.linked_mailbox||mailboxMenu.options[0]?.value||"";form.append(mailboxMenu);
  }
  if(email&&source.sender&&source.recipient&&source.subject)card.append(text("p",`Only login messages from ${source.sender} to ${source.recipient} with subject “${source.subject}”.`));
  for(const name of names){const input=document.createElement("input");input.type=name==="username"?"text":"password";input.required=true;input.placeholder=name==="seed"?"Authenticator setup key or otpauth link":name==="password"?"Mailbox application password":name;input.setAttribute("aria-label",input.placeholder);fields[name]=input;form.append(input);}
  if(mailboxMenu){if(!source.enrolled&&mailboxMenu.options.length===2){const saved=(state.mailboxes||[]).find(x=>x.id===mailboxMenu.options[1].value);if(saved?.connection_check?.status==="VERIFIED")mailboxMenu.selectedIndex=1;}mailboxMenu.onchange=()=>Object.values(fields).forEach(input=>{input.disabled=!!mailboxMenu.value;input.hidden=input.disabled;if(input.disabled)input.value="";});mailboxMenu.onchange();}
  if(source.kind==="mac_messages")card.append(text("p","Enable iPhone text forwarding to this Mac and grant the signed Account Access app Full Disk Access in macOS privacy settings."));
  if(source.kind==="gmail")card.append(text("p","Choose a connected, checked Gmail mailbox to avoid signing in again. Only this website's configured login messages are used. If no mailbox is offered, connect and check the configured Google account above first."));
  const submit=text("button",source.enrolled?"Update verification":"Enable verification");submit.type="submit";form.append(submit);
  const operationKey="factor:"+source.id;const gmailReady=source.kind!=="gmail"||!!(mailboxMenu?.value&&source.setup_context&&source.setup_revision);submit.disabled=setupOperations.has(operationKey)||!gmailReady;if(submit.disabled)form.querySelectorAll("input,select").forEach(field=>field.disabled=true);
  form.onsubmit=async event=>{event.preventDefault();if(locallyPaused||setupOperations.has(operationKey)||!gmailReady)return;const operation={cancelled:false,epoch:setupEpoch};setupOperations.set(operationKey,operation);submit.disabled=true;const controls=[...form.querySelectorAll("input,select")].map(field=>[field,field.disabled]);controls.forEach(([field])=>field.disabled=true);try{const credential=mailboxMenu?.value?{mailbox:mailboxMenu.value}:Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,v.value]));if(source.kind==="gmail"){credential.setup_context=source.setup_context;credential.setup_revision=source.setup_revision;}if(source.kind==="mac_messages")credential.enabled=true;Object.values(fields).filter(field=>field.type==="password").forEach(field=>field.value="");
  await call("/owner/source",{source:source.id,credential});Object.values(fields).forEach(x=>x.value="");if(operation.cancelled||operation.epoch!==setupEpoch||locallyPaused)return;if(email)await call("/owner/source/check",{source:source.id});for(const account of source.accounts){if(operation.cancelled||operation.epoch!==setupEpoch||locallyPaused)return;const current=state.accounts.find(x=>x.account===account);if(!current?.challenges?.some(x=>["captcha","passkey","device","admin","action","recovery","unknown"].includes(x.kind)))await call("/owner/verify",{account});}message("Verification saved locally. Check each website's sign-in status below.");}catch(e){if(!operation.cancelled&&operation.epoch===setupEpoch&&!locallyPaused)problem(e);}finally{if(setupOperations.get(operationKey)===operation)setupOperations.delete(operationKey);if(!locallyPaused){submit.disabled=locallyPaused||!gmailReady;controls.forEach(([field,disabled])=>field.disabled=disabled);await refresh().catch(problem);}}};
  if(source.kind==="phone_relay"){const pair=text("button","Pair Android companion");pair.type="button";pair.onclick=async()=>{try{const result=await call("/owner/phone/pair",{source:source.id});await navigator.clipboard.writeText(JSON.stringify(result));message("Pairing copied. Paste into your Android companion on the same private Wi-Fi.");}catch(e){problem(e);}};card.append(pair);}
  if(source.enrolled){const disable=text("button","Disable verification");disable.type="button";disable.onclick=async()=>{try{await call("/owner/source/revoke",{source:source.id});await refresh();}catch(e){problem(e);}};card.append(disable);}
  card.append(form);container.append(card);
 }
 if(!state.code_sources.length&&!state.sms_setups?.length){const empty=text("div","");empty.className="card";empty.append(text("h2","Connect a website"),text("p","You can save your mailbox now. Website verification methods appear after you connect a supported account."));container.append(empty);}
}
