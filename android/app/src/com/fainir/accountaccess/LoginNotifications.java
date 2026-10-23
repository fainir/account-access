package com.fainir.accountaccess;

import android.app.Notification;
import android.os.Bundle;
import android.os.SystemClock;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import org.json.JSONObject;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class LoginNotifications extends NotificationListenerService {
 final ThreadPoolExecutor worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),new ThreadPoolExecutor.AbortPolicy());
 void status(String value){getSharedPreferences("settings",0).edit().putString("last_status",value).apply();}
 static String hex(byte[] bytes){StringBuilder s=new StringBuilder();for(byte b:bytes)s.append(String.format("%02x",b&255));return s.toString();}
 @Override public void onListenerConnected(){getSharedPreferences("settings",0).edit().putBoolean("listener_ready",true).apply();}
 @Override public void onListenerDisconnected(){getSharedPreferences("settings",0).edit().putBoolean("listener_ready",false).apply();}
 @Override public void onNotificationPosted(StatusBarNotification notification){
  if(!notification.getPackageName().equals(getSharedPreferences("settings",0).getString("sms_package",""))){getSharedPreferences("settings",0).edit().putString("last_status","ignored_other_app").apply();return;}
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
   worker.execute(()->send(pair,payload));
  }catch(RejectedExecutionException ignored){status("delivery_queue_unavailable");
  }catch(Exception ignored){status("notification_unavailable");}
 }
 void send(JSONObject pair,JSONObject payload){
  try{
   status("delivery_preparing");
   final String fingerprint=pair.getString("certificate_sha256");
   X509TrustManager trust=new X509TrustManager(){
    public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}
    public void checkClientTrusted(X509Certificate[] chain,String auth) throws java.security.cert.CertificateException{throw new java.security.cert.CertificateException("Client verification unsupported");}
    public void checkServerTrusted(X509Certificate[] chain,String auth) throws java.security.cert.CertificateException{
     try{if(chain.length<1)throw new Exception();chain[0].checkValidity();String actual=hex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));if(!MessageDigest.isEqual(fingerprint.getBytes("US-ASCII"),actual.getBytes("US-ASCII")))throw new Exception();}catch(Exception e){throw new java.security.cert.CertificateException("Computer certificate changed; pair again");}
    }
   };
   SSLContext context=SSLContext.getInstance("TLS");context.init(null,new TrustManager[]{trust},null);
   byte[] data=payload.toString().getBytes("UTF-8");
   final URL destination=new URL(pair.getString("url"));
   final String token=pair.getString("token");
   final double received=payload.getDouble("received_at")*1000;
   final long began=SystemClock.elapsedRealtime();
   final long lifetime=(long)Math.max(0,Math.min(120000,received+120000-System.currentTimeMillis()));
   boolean delivered=LoginDelivery.send(()->{
    status("delivery_connecting");
    HttpsURLConnection connection=(HttpsURLConnection)destination.openConnection();
    try{
     connection.setSSLSocketFactory(context.getSocketFactory());connection.setConnectTimeout(3000);connection.setReadTimeout(3000);connection.setInstanceFollowRedirects(false);connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setFixedLengthStreamingMode(data.length);connection.setRequestProperty("Authorization","Bearer "+token);connection.setRequestProperty("Content-Type","application/json");
     try(java.io.OutputStream output=connection.getOutputStream()){output.write(data);}
     return connection.getResponseCode();
    }finally{connection.disconnect();}
   },()->{
    status("delivery_checking_pairing");
    if(!ComputerAssociation.ready(this)){status("computer_permission_required");return false;}
    double age=System.currentTimeMillis()-received;
    if(age< -5000 || age>120000 || SystemClock.elapsedRealtime()-began>lifetime){status("delivery_expired");return false;}
    JSONObject current=Pairing.load(this);
    if(current==null || !MessageDigest.isEqual(token.getBytes("UTF-8"),current.getString("token").getBytes("UTF-8"))){status("delivery_pairing_changed");return false;}
    for(String key:new String[]{"url","certificate_sha256","source","sender","recipient","template"})if(!pair.getString(key).equals(current.getString(key))){status("delivery_pairing_changed");return false;}
    return true;
   },Thread::sleep,value->getSharedPreferences("settings",0).edit().putString("last_status",value).apply());
   if(delivered)getSharedPreferences("settings",0).edit().putLong("last_delivery",System.currentTimeMillis()).putString("last_status","delivered").apply();
  }catch(InterruptedException interrupted){Thread.currentThread().interrupt();
  }catch(Exception ignored){getSharedPreferences("settings",0).edit().putString("last_status","link_error_"+ignored.getClass().getSimpleName()).apply();}
 }
 @Override public void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
