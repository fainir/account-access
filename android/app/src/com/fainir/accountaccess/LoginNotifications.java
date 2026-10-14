package com.fainir.accountaccess;

import android.app.Notification;
import android.os.Bundle;
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
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class LoginNotifications extends NotificationListenerService {
 final ThreadPoolExecutor worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(8),new ThreadPoolExecutor.DiscardPolicy());
 static String hex(byte[] bytes){StringBuilder s=new StringBuilder();for(byte b:bytes)s.append(String.format("%02x",b&255));return s.toString();}
 @Override public void onListenerConnected(){getSharedPreferences("settings",0).edit().putBoolean("listener_ready",true).apply();}
 @Override public void onListenerDisconnected(){getSharedPreferences("settings",0).edit().putBoolean("listener_ready",false).apply();}
 @Override public void onNotificationPosted(StatusBarNotification notification){
  if(!notification.getPackageName().equals(getSharedPreferences("settings",0).getString("sms_package","")))return;
  if(Math.abs(System.currentTimeMillis()-notification.getPostTime())>120000)return;
  try{
   JSONObject pair=Pairing.load(this);if(pair==null)return;
   Bundle extras=notification.getNotification().extras;
   String sender=String.valueOf(extras.getCharSequence(Notification.EXTRA_TITLE,""));
   String body=String.valueOf(extras.getCharSequence(Notification.EXTRA_BIG_TEXT,extras.getCharSequence(Notification.EXTRA_TEXT,""))).trim();
   String template=pair.getString("template");int split=template.indexOf("{code}");
   String regex=Pattern.quote(template.substring(0,split))+"[0-9]{6}"+Pattern.quote(template.substring(split+6));
   if(!sender.equals(pair.getString("sender")) || !body.matches(regex))return;
   JSONObject payload=new JSONObject();payload.put("id",hex(MessageDigest.getInstance("SHA-256").digest((notification.getKey()+body).getBytes("UTF-8"))));payload.put("sender",sender);payload.put("recipient",pair.getString("recipient"));payload.put("body",body);payload.put("received_at",notification.getPostTime()/1000.0);
   worker.execute(()->send(pair,payload));
  }catch(Exception ignored){}
 }
 void send(JSONObject pair,JSONObject payload){
  try{
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
   for(int attempt=0;attempt<30;attempt++){
    if(System.currentTimeMillis()/1000.0-payload.getDouble("received_at")>120)return;
    HttpsURLConnection connection=(HttpsURLConnection)new URL(pair.getString("url")).openConnection();
    connection.setSSLSocketFactory(context.getSocketFactory());connection.setConnectTimeout(3000);connection.setReadTimeout(3000);connection.setInstanceFollowRedirects(false);connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setFixedLengthStreamingMode(data.length);connection.setRequestProperty("Authorization","Bearer "+pair.getString("token"));connection.setRequestProperty("Content-Type","application/json");
    try{try(java.io.OutputStream output=connection.getOutputStream()){output.write(data);}int status=connection.getResponseCode();if(status==200){getSharedPreferences("settings",0).edit().putLong("last_delivery",System.currentTimeMillis()).apply();return;}if(status!=403)return;}finally{connection.disconnect();}
    Thread.sleep(1000);
   }
  }catch(Exception ignored){}
 }
 @Override public void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
