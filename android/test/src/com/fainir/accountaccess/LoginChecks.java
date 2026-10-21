package com.fainir.accountaccess;

import android.app.Instrumentation;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Bundle;
import android.os.SystemClock;
import org.json.JSONObject;

public final class LoginChecks extends Instrumentation {
 static final String NOTIFICATION_TAG="account-access-fixture";
 Bundle args;
 @Override public void onCreate(Bundle arguments){args=arguments;start();}
 @Override public void onStart(){
  Bundle result=new Bundle();
  NotificationManager manager=null;
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
   context.startActivity(new android.content.Intent(context,MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
   waitForIdleSync();
   Thread.sleep(500);
   context.getSharedPreferences("settings",0).edit().putString("sms_package",context.getPackageName()).remove("last_delivery").putBoolean("listener_ready",false).commit();
   Bundle prepared=new Bundle();prepared.putString("phase","PAIRING_AND_FILTER_READY");sendStatus(1,prepared);
   long readyDeadline=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<readyDeadline&&!context.getSharedPreferences("settings",0).getBoolean("listener_ready",false))Thread.sleep(100);
   if(!context.getSharedPreferences("settings",0).getBoolean("listener_ready",false))throw new Exception("Listener did not connect after instrumentation setup");
   manager=(NotificationManager)context.getSystemService(Context.NOTIFICATION_SERVICE);
   manager.createNotificationChannel(new NotificationChannel("account-access-check","Example login code",NotificationManager.IMPORTANCE_HIGH));
   String body=expected.getString("template").replace("{code}",args.getString("login_code"));
   manager.notify(NOTIFICATION_TAG,7,new Notification.Builder(context,"account-access-check").setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(expected.getString("sender")).setContentText("Notification source check; no login code").build());
   // Notification posting is asynchronous. Wait for this exact fixture, rather
   // than assuming Android has published it after an arbitrary 300 ms delay.
   android.service.notification.StatusBarNotification posted=null;
   long postingDeadline=SystemClock.elapsedRealtime()+5000;
   while(posted==null&&SystemClock.elapsedRealtime()<postingDeadline){
    for(android.service.notification.StatusBarNotification candidate:manager.getActiveNotifications()){
     if(candidate.getId()==7&&NOTIFICATION_TAG.equals(candidate.getTag())&&context.getPackageName().equals(candidate.getPackageName())){posted=candidate;break;}
    }
    if(posted==null)Thread.sleep(100);
   }
   if(posted==null)throw new Exception("Controlled test notification did not appear");
   context.getSharedPreferences("settings",0).edit().putString("sms_package",posted.getPackageName()).commit();
   manager.cancel(NOTIFICATION_TAG,7);
   manager.notify(NOTIFICATION_TAG,8,new Notification.Builder(context,"account-access-check").setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(expected.getString("sender")).setContentText(body).setStyle(new Notification.BigTextStyle().bigText(body)).build());
   long deadline=System.currentTimeMillis()+15000;while(System.currentTimeMillis()<deadline&&context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)Thread.sleep(100);
   if(context.getSharedPreferences("settings",0).getLong("last_delivery",0)==0)throw new Exception("Notification not delivered; listener_ready="+context.getSharedPreferences("settings",0).getBoolean("listener_ready",false)+"; status="+context.getSharedPreferences("settings",0).getString("last_status","none")+"; notifications="+manager.getActiveNotifications().length+"; enabled="+manager.areNotificationsEnabled()+"; package="+context.getPackageName());
   manager.cancel(NOTIFICATION_TAG,8);result.putString("result","PASS: Keystore encryption, destination restriction, actual Android notification, and certificate-pinned HTTPS delivery");finish(-1,result);
  }catch(Exception e){result.putString("result","FAIL: "+e.getMessage());finish(0,result);}
  finally{if(manager!=null){manager.cancel(NOTIFICATION_TAG,7);manager.cancel(NOTIFICATION_TAG,8);}}
 }
}
