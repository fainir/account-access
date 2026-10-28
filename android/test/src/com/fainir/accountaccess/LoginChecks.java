package com.fainir.accountaccess;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.view.accessibility.AccessibilityNodeInfo;
import android.app.UiAutomation;
import java.util.ArrayDeque;
import org.json.JSONObject;

public final class LoginChecks extends Instrumentation {
 static final String NOTIFICATION_TAG="account-access-fixture";
 Bundle args;
 void enterManualCode(String code) throws Exception {
  UiAutomation automation=getUiAutomation();
  AccessibilityNodeInfo input=findNode(automation,"Account Access login code input");
  if(input==null)throw new Exception("Manual code field is missing from the phone app");
  input.performAction(AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS);
  Bundle value=new Bundle();value.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,code);
  if(!input.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,value))throw new Exception("Manual code field rejected test input");
  waitForIdleSync();
  AccessibilityNodeInfo button=findNode(automation,"Send login code to paired computer");
  if(button==null)throw new Exception("Manual delivery button is missing from the phone app");
  button.performAction(AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS);
  if(!button.performAction(AccessibilityNodeInfo.ACTION_CLICK))throw new Exception("Manual delivery button could not be activated");
  waitForIdleSync();
 }
 AccessibilityNodeInfo findNode(UiAutomation automation,String description) throws Exception {
  long deadline=System.currentTimeMillis()+5000;
  while(System.currentTimeMillis()<deadline){
   AccessibilityNodeInfo root=automation.getRootInActiveWindow();
   if(root!=null){
    ArrayDeque<AccessibilityNodeInfo> pending=new ArrayDeque<>();pending.add(root);
    while(!pending.isEmpty()){
     AccessibilityNodeInfo node=pending.removeFirst();
     CharSequence actual=node.getContentDescription();
     if(description.contentEquals(actual))return node;
     for(int i=0;i<node.getChildCount();i++){AccessibilityNodeInfo child=node.getChild(i);if(child!=null)pending.addLast(child);}
    }
   }
   Thread.sleep(100);
  }
  return null;
 }
 @Override public void onCreate(Bundle arguments){args=arguments;start();}
 @Override public void onStart(){
  Bundle result=new Bundle();
  try{
   LoginDeliveryChecks.run();
   Context context=getTargetContext();
   String path=args.getString("pairing_file");
   java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();
   try(java.io.InputStream stream=new java.io.FileInputStream(path)){byte[] data=new byte[4096];int n;while((n=stream.read(data))>0)bytes.write(data,0,n);}
   String raw=new String(bytes.toByteArray(),"UTF-8");JSONObject expected=new JSONObject(raw);
   PhoneCodeDeliveryChecks.run(expected);
   Pairing.save(context,raw);JSONObject restored=Pairing.load(context);
   if(!expected.getString("token").equals(restored.getString("token")))throw new Exception("Keystore round-trip failed");
   if(context.getSharedPreferences("link",0).getString("payload","").contains(expected.getString("token")))throw new Exception("Plaintext pairing persisted");
   JSONObject invalid=new JSONObject(raw);invalid.put("url","https://8.8.8.8/v1/login-code/"+expected.getString("source"));
   boolean rejected=false;try{Pairing.validate(invalid);}catch(Exception e){rejected=true;}if(!rejected)throw new Exception("Public ingress accepted");
   boolean associationBlocked=ComputerAssociationChecks.run(this,raw);
   context.startActivity(new android.content.Intent(context,MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
   waitForIdleSync();
   Thread.sleep(500);
   context.getSharedPreferences("settings",0).edit().putString("sms_package",getContext().getPackageName()).remove("last_delivery").remove("last_status").putBoolean("listener_ready",false).commit();
   Bundle prepared=new Bundle();prepared.putString("phase","PAIRING_AND_FILTER_READY");sendStatus(1,prepared);
   long readyDeadline=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<readyDeadline&&!context.getSharedPreferences("settings",0).getBoolean("listener_ready",false))Thread.sleep(100);
   if(!context.getSharedPreferences("settings",0).getBoolean("listener_ready",false))throw new Exception("Listener did not connect after instrumentation setup");
   Bundle notificationReady=new Bundle();notificationReady.putString("phase","NOTIFICATION_READY");sendStatus(1,notificationReady);
   if(associationBlocked){
    String manualCode=args.getString("login_code","");
    enterManualCode(manualCode);
    long manualDeadline=System.currentTimeMillis()+5000;while(System.currentTimeMillis()<manualDeadline && !"computer_permission_required".equals(context.getSharedPreferences("settings",0).getString("last_status","")))Thread.sleep(50);
    if(!"computer_permission_required".equals(context.getSharedPreferences("settings",0).getString("last_status","")) || context.getSharedPreferences("settings",0).getLong("last_delivery",0)!=0)throw new Exception("Manual code escaped without Android's computer association");
    for(Object value:context.getSharedPreferences("settings",0).getAll().values())if(value instanceof String && ((String)value).contains(manualCode))throw new Exception("Manual login code was persisted");
    long blockedDeadline=System.currentTimeMillis()+8000;
    while(System.currentTimeMillis()<blockedDeadline && !"computer_permission_required".equals(context.getSharedPreferences("settings",0).getString("last_status","")))Thread.sleep(100);
    if(!"computer_permission_required".equals(context.getSharedPreferences("settings",0).getString("last_status","")) || context.getSharedPreferences("settings",0).getLong("last_delivery",0)!=0)throw new Exception("Unassociated notification did not stop safely");
    java.io.ByteArrayOutputStream noiseBytes=new java.io.ByteArrayOutputStream();
    android.os.ParcelFileDescriptor noise=getUiAutomation().executeShellCommand("cmd notification post -v -t 'Unrelated test notification' account-access-unrelated-fixture 'No login code in this notification'");
    try(java.io.InputStream stream=new android.os.ParcelFileDescriptor.AutoCloseInputStream(noise)){
     byte[] buffer=new byte[4096];int n;while((n=stream.read(buffer))>0){noiseBytes.write(buffer,0,n);if(noiseBytes.size()>65536)throw new Exception("Unrelated notification acknowledgement exceeded limit");}
    }
    if(!java.util.regex.Pattern.compile("(?m)^posted: *$").matcher(new String(noiseBytes.toByteArray(),"UTF-8")).find())throw new Exception("Unrelated test notification was not confirmed");
    Bundle blocked=new Bundle();blocked.putString("phase","UNRELATED_NOTIFICATION_POSTED");sendStatus(1,blocked);
    waitForIdleSync();
    long stableUntil=android.os.SystemClock.elapsedRealtime()+5000;
    while(android.os.SystemClock.elapsedRealtime()<stableUntil){
     if(!"computer_permission_required".equals(context.getSharedPreferences("settings",0).getString("last_status","")) || context.getSharedPreferences("settings",0).getLong("last_delivery",0)!=0)throw new Exception("Unrelated notification changed blocked login status");
     Thread.sleep(100);
    }
    result.putString("result","PASS_BLOCKED: Android 15 refused notification and owner-entered code without computer association; code was not persisted; positive Bluetooth pairing not tested");finish(-1,result);return;
   }
   if("manual".equals(args.getString("delivery_mode","notification"))){
    String manualCode=args.getString("login_code","");
    enterManualCode(manualCode);
    long manualDeadline=System.currentTimeMillis()+15000;while(System.currentTimeMillis()<manualDeadline && context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)Thread.sleep(100);
    if(context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0 || !"delivered".equals(context.getSharedPreferences("settings",0).getString("last_status","none")))throw new Exception("Owner-entered SMS code did not reach the paired computer");
    for(Object value:context.getSharedPreferences("settings",0).getAll().values())if(value instanceof String && ((String)value).contains(manualCode))throw new Exception("Manual login code was persisted");
    result.putString("result","PASS_MANUAL: phone UI sent an owner-entered code through the paired, certificate-pinned connection without persisting it");finish(-1,result);return;
   }
   long deadline=System.currentTimeMillis()+15000;while(System.currentTimeMillis()<deadline&&context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)Thread.sleep(100);
   if(context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)throw new Exception("Notification not delivered; listener_ready="+context.getSharedPreferences("settings",0).getBoolean("listener_ready",false)+"; status="+context.getSharedPreferences("settings",0).getString("last_status","none"));
   result.putString("result","PASS: Keystore encryption, destination restriction, actual Android notification, and certificate-pinned HTTPS delivery");finish(-1,result);
  }catch(Exception e){result.putString("result","FAIL: "+e.getMessage());finish(0,result);}
 }
}
