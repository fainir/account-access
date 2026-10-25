package com.fainir.accountaccess;

import android.app.Instrumentation;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import org.json.JSONArray;
import org.json.JSONObject;
import java.security.MessageDigest;

/** Fictional pairing only; invoked by the guarded hosted-emulator harness. */
public final class PairingUpgradeChecks extends Instrumentation {
 Bundle args;
 @Override public void onCreate(Bundle arguments){args=arguments;start();}
 static JSONObject fictional() throws Exception {
  return new JSONObject().put("version",1).put("url","https://192.168.1.2:9443/v1/login-code/upgrade-fixture")
   .put("certificate_sha256","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
   .put("source","upgrade-fixture").put("token","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
   .put("sender","Fictional sender").put("recipient","Fictional owner").put("template","Fictional login: {code}")
   .put("bluetooth_service_uuid","11111111-2222-4333-8444-555555555555");
 }
 static String encryptedDigest(Context context) throws Exception {
  SharedPreferences link=context.getSharedPreferences("link",0);
  String iv=link.getString("iv",null),payload=link.getString("payload",null);
  if(iv==null||payload==null||payload.contains(fictional().getString("token")))throw new Exception();
  byte[] bytes=new JSONArray().put(iv).put(payload).toString().getBytes("UTF-8");
  return LoginNotifications.hex(MessageDigest.getInstance("SHA-256").digest(bytes));
 }
 @Override public void onStart(){
  Bundle result=new Bundle();
  try {
   Context context=getTargetContext();String phase=args.getString("phase");
   long version=context.getPackageManager().getPackageInfo(context.getPackageName(),0).getLongVersionCode();
   JSONObject expected=fictional();SharedPreferences witness=context.getSharedPreferences("upgrade_fixture",0);
   if("create".equals(phase)){
    if(version!=2||Pairing.load(context)!=null||witness.contains("encrypted_digest"))throw new Exception();
    Pairing.save(context,expected.toString());
    if(!witness.edit().putString("encrypted_digest",encryptedDigest(context)).commit())throw new Exception();
    if(!context.getSharedPreferences("settings",0).edit().putString("sms_package","fictional.sms.app").putString("last_status","fixture_preserved").commit())throw new Exception();
   }else if("verify".equals(phase)){
    if(version!=3||!encryptedDigest(context).equals(witness.getString("encrypted_digest","")))throw new Exception();
    SharedPreferences settings=context.getSharedPreferences("settings",0);
    if(!"fictional.sms.app".equals(settings.getString("sms_package",""))||!"fixture_preserved".equals(settings.getString("last_status","")))throw new Exception();
   }else throw new Exception();
   JSONObject restored=Pairing.load(context);
   if(restored==null||!ComputerAssociation.binding(expected).equals(ComputerAssociation.binding(restored)))throw new Exception();
   if(android.os.Build.VERSION.SDK_INT>=35&&ComputerAssociation.ready(context))throw new Exception();
   result.putString("result","PASS: release_update_pairing_"+("create".equals(phase)?"created":"preserved"));finish(-1,result);
  }catch(Exception failure){result.putString("result","FAIL: release_update_pairing_check");finish(0,result);}
 }
}
