package com.fainir.accountaccess;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import org.json.JSONObject;

public final class LoginChecks extends Instrumentation {
 static final String NOTIFICATION_TAG="account-access-fixture";
 Bundle args;
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
   Pairing.save(context,raw);JSONObject restored=Pairing.load(context);
   if(!expected.getString("token").equals(restored.getString("token")))throw new Exception("Keystore round-trip failed");
   if(context.getSharedPreferences("link",0).getString("payload","").contains(expected.getString("token")))throw new Exception("Plaintext pairing persisted");
   JSONObject invalid=new JSONObject(raw);invalid.put("url","https://8.8.8.8/v1/login-code/"+expected.getString("source"));
   boolean rejected=false;try{Pairing.validate(invalid);}catch(Exception e){rejected=true;}if(!rejected)throw new Exception("Public ingress accepted");
   ComputerAssociationChecks.run(this,raw);
   context.startActivity(new android.content.Intent(context,MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
   waitForIdleSync();
   Thread.sleep(500);
   context.getSharedPreferences("settings",0).edit().putString("sms_package",getContext().getPackageName()).remove("last_delivery").putBoolean("listener_ready",false).commit();
   Bundle prepared=new Bundle();prepared.putString("phase","PAIRING_AND_FILTER_READY");sendStatus(1,prepared);
   long readyDeadline=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<readyDeadline&&!context.getSharedPreferences("settings",0).getBoolean("listener_ready",false))Thread.sleep(100);
   if(!context.getSharedPreferences("settings",0).getBoolean("listener_ready",false))throw new Exception("Listener did not connect after instrumentation setup");
   Bundle notificationReady=new Bundle();notificationReady.putString("phase","NOTIFICATION_READY");sendStatus(1,notificationReady);
   long deadline=System.currentTimeMillis()+15000;while(System.currentTimeMillis()<deadline&&context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)Thread.sleep(100);
   if(context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)throw new Exception("Notification not delivered; listener_ready="+context.getSharedPreferences("settings",0).getBoolean("listener_ready",false)+"; status="+context.getSharedPreferences("settings",0).getString("last_status","none"));
   result.putString("result","PASS: Keystore encryption, destination restriction, actual Android notification, and certificate-pinned HTTPS delivery");finish(-1,result);
  }catch(Exception e){result.putString("result","FAIL: "+e.getMessage());finish(0,result);}
 }
}
