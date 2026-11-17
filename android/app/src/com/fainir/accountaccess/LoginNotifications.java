package com.fainir.accountaccess;

import android.app.Notification;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import org.json.JSONObject;
import java.security.MessageDigest;
import java.util.regex.Pattern;

public final class LoginNotifications extends NotificationListenerService {
 void status(String value){getSharedPreferences("settings",0).edit().putString("last_status",value).apply();}
 static String hex(byte[] bytes){StringBuilder s=new StringBuilder();for(byte b:bytes)s.append(String.format("%02x",b&255));return s.toString();}
 @Override public void onListenerConnected(){getSharedPreferences("settings",0).edit().putBoolean("listener_ready",true).apply();}
 @Override public void onListenerDisconnected(){getSharedPreferences("settings",0).edit().putBoolean("listener_ready",false).apply();}
 @Override public void onNotificationPosted(StatusBarNotification notification){
  // Unrelated notifications must not replace the last login delivery status.
  if(!notification.getPackageName().equals(getSharedPreferences("settings",0).getString("sms_package","")))return;
  if(Math.abs(System.currentTimeMillis()-notification.getPostTime())>120000)return;
  if(!ComputerAssociation.ready(this)){getSharedPreferences("settings",0).edit().putString("last_status","computer_permission_required").apply();return;}
  try{
   status("notification_reading_pairing");
   JSONObject pair=Pairing.load(this);if(pair==null){getSharedPreferences("settings",0).edit().putString("last_status","pairing_unavailable").apply();return;}
   Bundle extras=notification.getNotification().extras;
   String sender=String.valueOf(extras.getCharSequence(Notification.EXTRA_TITLE,""));
   String body=String.valueOf(extras.getCharSequence(Notification.EXTRA_BIG_TEXT,extras.getCharSequence(Notification.EXTRA_TEXT,""))).trim();
   String template=pair.getString("template");int split=template.indexOf("{code}");
   String regex=Pattern.quote(template.substring(0,split))+"[0-9]{6}"+Pattern.quote(template.substring(split+6));
   if(!sender.equals(pair.getString("sender")) || !body.matches(regex)){getSharedPreferences("settings",0).edit().putString("last_status","filter_mismatch").apply();return;}
   JSONObject payload=new JSONObject();payload.put("id",hex(MessageDigest.getInstance("SHA-256").digest((notification.getKey()+body).getBytes("UTF-8"))));payload.put("sender",sender);payload.put("recipient",pair.getString("recipient"));payload.put("body",body);payload.put("received_at",notification.getPostTime()/1000.0);
   status("delivery_queued");
   PhoneCodeDelivery.submitNotification(this,pair,payload);
  }catch(Exception ignored){status("notification_unavailable");}
 }
}
