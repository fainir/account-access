package com.fainir.accountaccess;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import org.json.JSONObject;
import java.net.URI;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class Pairing {
 static final String ALIAS="account-access-phone-pairing-v1";
 static void validate(JSONObject p) throws Exception {
  URI u=new URI(p.getString("url"));
  String host=u.getHost();
  if(!"https".equals(u.getScheme()) || u.getUserInfo()!=null || u.getQuery()!=null || u.getFragment()!=null || host==null || !host.matches("[0-9.]+") || !u.getPath().equals("/v1/login-code/"+p.getString("source")))throw new Exception("Invalid pairing destination");
  String[] parts=host.split("\\."); if(parts.length!=4)throw new Exception("Invalid Wi-Fi address");
  int a=Integer.parseInt(parts[0]),b=Integer.parseInt(parts[1]);
  for(String part:parts)if(Integer.parseInt(part)>255)throw new Exception("Invalid Wi-Fi address");
  if(!(a==10 || (a==172 && b>=16 && b<=31) || (a==192 && b==168)))throw new Exception("Use private Wi-Fi");
  if(p.getInt("version")!=1 || !p.getString("certificate_sha256").matches("[0-9a-f]{64}") || !p.getString("source").matches("[a-z][a-z0-9_-]{0,63}") || !p.getString("token").matches("[A-Za-z0-9_-]{40,100}"))throw new Exception("Invalid pairing");
  String template=p.getString("template");if(template.length()>2000 || !template.contains("{code}") || template.indexOf("{code}")!=template.lastIndexOf("{code}"))throw new Exception("Invalid login template");
  if(p.getString("sender").isEmpty() || p.getString("recipient").isEmpty())throw new Exception("Missing login source");
  if(p.has("bluetooth_service_uuid") && !p.getString("bluetooth_service_uuid").matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"))throw new Exception("Invalid computer discovery identity");
 }
 static SecretKey key() throws Exception {
  KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
  if(!store.containsAlias(ALIAS)){
   KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
   generator.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());generator.generateKey();
  }
  return (SecretKey)store.getKey(ALIAS,null);
 }
 static synchronized void save(Context c,String raw) throws Exception {
  JSONObject object=new JSONObject(raw);validate(object);
  Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());
  byte[] encrypted=cipher.doFinal(object.toString().getBytes("UTF-8"));
  ComputerAssociation.clear(c);
  if(!c.getSharedPreferences("link",0).edit().putString("iv",Base64.encodeToString(cipher.getIV(),Base64.NO_WRAP)).putString("payload",Base64.encodeToString(encrypted,Base64.NO_WRAP)).commit())throw new Exception("Pairing could not be saved");
 }
 static synchronized JSONObject load(Context c) throws Exception {
  android.content.SharedPreferences prefs=c.getSharedPreferences("link",0);String payload=prefs.getString("payload",null);if(payload==null)return null;
  Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,Base64.decode(prefs.getString("iv",""),Base64.NO_WRAP)));
  JSONObject object=new JSONObject(new String(cipher.doFinal(Base64.decode(payload,Base64.NO_WRAP)),"UTF-8"));validate(object);return object;
 }
 static synchronized void clear(Context c) throws Exception {
  if(!c.getSharedPreferences("link",0).edit().clear().commit())throw new Exception("Pairing could not be removed");
  ComputerAssociation.clear(c);
 }
}
