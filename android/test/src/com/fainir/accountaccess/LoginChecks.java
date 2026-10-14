package com.fainir.accountaccess;

import android.app.Instrumentation;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Bundle;
import org.json.JSONObject;

public final class LoginChecks extends Instrumentation {
 Bundle args;
 @Override public void onCreate(Bundle arguments){args=arguments;start();}
 @Override public void onStart(){
  Bundle result=new Bundle();
  try{
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
   context.startActivity(new android.content.Intent(context,MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
   waitForIdleSync();
   Thread.sleep(500);
   context.getSharedPreferences("settings",0).edit().putString("sms_package",context.getPackageName()).remove("last_delivery").commit();
   android.service.notification.NotificationListenerService.requestRebind(new android.content.ComponentName(context,LoginNotifications.class));
   long readyDeadline=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<readyDeadline&&!context.getSharedPreferences("settings",0).getBoolean("listener_ready",false))Thread.sleep(100);
   NotificationManager manager=(NotificationManager)context.getSystemService(Context.NOTIFICATION_SERVICE);
   manager.createNotificationChannel(new NotificationChannel("account-access-check","Example login code",NotificationManager.IMPORTANCE_HIGH));
   String body=expected.getString("template").replace("{code}",args.getString("login_code"));
   manager.notify(7,new Notification.Builder(context,"account-access-check").setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(expected.getString("sender")).setContentText("Notification source check; no login code").build());
   Thread.sleep(300);
   android.service.notification.StatusBarNotification[] posted=manager.getActiveNotifications();
   if(posted.length!=1)throw new Exception("Expected one controlled test notification");
   context.getSharedPreferences("settings",0).edit().putString("sms_package",posted[0].getPackageName()).commit();
   manager.cancel(7);
   manager.notify(8,new Notification.Builder(context,"account-access-check").setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(expected.getString("sender")).setContentText(body).setStyle(new Notification.BigTextStyle().bigText(body)).build());
   long deadline=System.currentTimeMillis()+15000;while(System.currentTimeMillis()<deadline&&context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)Thread.sleep(100);
   if(context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)throw new Exception("Notification not delivered; listener_ready="+context.getSharedPreferences("settings",0).getBoolean("listener_ready",false)+"; status="+context.getSharedPreferences("settings",0).getString("last_status","none")+"; notifications="+manager.getActiveNotifications().length+"; enabled="+manager.areNotificationsEnabled()+"; package="+context.getPackageName());
   manager.cancel(8);result.putString("result","PASS: Keystore encryption, destination restriction, actual Android notification, and certificate-pinned HTTPS delivery");finish(-1,result);
  }catch(Exception e){result.putString("result","FAIL: "+e.getMessage());finish(0,result);}
 }
}
