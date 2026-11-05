package com.fainir.accountaccess;

import android.content.Context;
import android.os.SystemClock;
import org.json.JSONObject;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/** One bounded, serialized path for notification and owner-entered SMS codes. */
final class PhoneCodeDelivery {
 private static final Pattern SIX_DIGITS=Pattern.compile("[0-9]{6}");
 private static final ThreadPoolExecutor worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(1),new ThreadPoolExecutor.AbortPolicy());
 private static final AtomicBoolean deliveryPending=new AtomicBoolean(false);

 interface Completion { void finished(String status); }

 static JSONObject manualPayload(JSONObject pair,String code,long receivedAtMillis,String id) throws Exception {
  Pairing.validate(pair);
  if(code==null || !SIX_DIGITS.matcher(code).matches())throw new IllegalArgumentException("invalid_login_code");
  if(id==null || id.isEmpty() || id.length()>128)throw new IllegalArgumentException("invalid_delivery_id");
  String template=pair.getString("template");
  if(template.indexOf("{code}")!=template.lastIndexOf("{code}"))throw new IllegalArgumentException("invalid_login_template");
  return new JSONObject().put("id",id).put("sender",pair.getString("sender"))
   .put("recipient",pair.getString("recipient")).put("body",template.replace("{code}",code))
   .put("received_at",receivedAtMillis/1000.0);
 }

 static void submitNotification(Context context,JSONObject pair,JSONObject payload){
  submit(context,pair,payload,null);
 }

 static void submitManualCode(Context context,String code,Completion completion){
  Context app=context.getApplicationContext();
  if(code==null || !SIX_DIGITS.matcher(code).matches()){
   status(app,"manual_code_invalid");finish(completion,"manual_code_invalid");return;
  }
  try{
   JSONObject pair=Pairing.load(app);
   if(pair==null){status(app,"pairing_unavailable");finish(completion,"pairing_unavailable");return;}
   if(!ComputerAssociation.ready(app)){status(app,"computer_permission_required");finish(completion,"computer_permission_required");return;}
   long last=app.getSharedPreferences("settings",0).getLong("last_delivery",0);
   if(last>0 && System.currentTimeMillis()-last<5000){status(app,"manual_code_recently_delivered");finish(completion,"manual_code_recently_delivered");return;}
   JSONObject payload=manualPayload(pair,code,System.currentTimeMillis(),"manual-"+UUID.randomUUID());
   submit(app,pair,payload,completion);
  }catch(Exception ignored){status(app,"pairing_unavailable");finish(completion,"pairing_unavailable");}
 }

 private static void submit(Context context,JSONObject pair,JSONObject payload,Completion completion){
  Context app=context.getApplicationContext();
  if(!deliveryPending.compareAndSet(false,true)){status(app,"delivery_queue_unavailable");finish(completion,"delivery_queue_unavailable");return;}
  status(app,"delivery_queued");
  try{worker.execute(()->{String result="notification_unavailable";try{result=send(app,pair,payload);}finally{deliveryPending.set(false);}finish(completion,result);});}
  catch(RejectedExecutionException ignored){deliveryPending.set(false);status(app,"delivery_queue_unavailable");finish(completion,"delivery_queue_unavailable");}
 }

 private static void finish(Completion completion,String value){if(completion!=null)completion.finished(value);}
 private static void status(Context context,String value){context.getSharedPreferences("settings",0).edit().putString("last_status",value).apply();}

 private static String send(Context context,JSONObject pair,JSONObject payload){
  final String[] latest={"notification_unavailable"};
  Consumer<String> update=value->{latest[0]=value;status(context,value);};
  try{
   update.accept("delivery_preparing");
   final String fingerprint=pair.getString("certificate_sha256");
   X509TrustManager trust=new X509TrustManager(){
    public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}
    public void checkClientTrusted(X509Certificate[] chain,String auth) throws java.security.cert.CertificateException{throw new java.security.cert.CertificateException("Client verification unsupported");}
    public void checkServerTrusted(X509Certificate[] chain,String auth) throws java.security.cert.CertificateException{
     try{if(chain.length<1)throw new Exception();chain[0].checkValidity();String actual=LoginNotifications.hex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));if(!MessageDigest.isEqual(fingerprint.getBytes("US-ASCII"),actual.getBytes("US-ASCII")))throw new Exception();}catch(Exception e){throw new java.security.cert.CertificateException("Computer certificate changed; pair again");}
    }
   };
   SSLContext tls=SSLContext.getInstance("TLS");tls.init(null,new TrustManager[]{trust},null);
   byte[] data=payload.toString().getBytes("UTF-8");
   final URL destination=new URL(pair.getString("url"));
   final String token=pair.getString("token");
   final double received=payload.getDouble("received_at")*1000;
   final long began=SystemClock.elapsedRealtime();
   final long lifetime=(long)Math.max(0,Math.min(120000,received+120000-System.currentTimeMillis()));
   boolean delivered=LoginDelivery.send(()->{
    update.accept("delivery_connecting");
    HttpsURLConnection connection=(HttpsURLConnection)destination.openConnection();
    try{
     connection.setSSLSocketFactory(tls.getSocketFactory());connection.setConnectTimeout(3000);connection.setReadTimeout(3000);connection.setInstanceFollowRedirects(false);connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setFixedLengthStreamingMode(data.length);connection.setRequestProperty("Authorization","Bearer "+token);connection.setRequestProperty("Content-Type","application/json");
     try(java.io.OutputStream output=connection.getOutputStream()){output.write(data);}
     return connection.getResponseCode();
    }finally{connection.disconnect();}
   },()->{
    update.accept("delivery_checking_pairing");
    if(!ComputerAssociation.ready(context)){update.accept("computer_permission_required");return false;}
    double age=System.currentTimeMillis()-received;
    if(age< -5000 || age>120000 || SystemClock.elapsedRealtime()-began>lifetime){update.accept("delivery_expired");return false;}
    JSONObject current=Pairing.load(context);
    if(current==null || !MessageDigest.isEqual(token.getBytes("UTF-8"),current.getString("token").getBytes("UTF-8"))){update.accept("delivery_pairing_changed");return false;}
    for(String key:new String[]{"url","certificate_sha256","source","sender","recipient","template"})if(!pair.getString(key).equals(current.getString(key))){update.accept("delivery_pairing_changed");return false;}
    return true;
   },Thread::sleep,update::accept);
   if(delivered){context.getSharedPreferences("settings",0).edit().putLong("last_delivery",System.currentTimeMillis()).putString("last_status","delivered").apply();latest[0]="delivered";}
   return latest[0];
  }catch(InterruptedException interrupted){Thread.currentThread().interrupt();return latest[0];
  }catch(Exception failure){latest[0]="link_error_"+failure.getClass().getSimpleName();status(context,latest[0]);return latest[0];}
 }
}
