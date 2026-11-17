package com.fainir.accountaccess;

import org.json.JSONObject;

/** Pure contract checks for the owner-entered Android SMS fallback. */
final class PhoneCodeDeliveryChecks {
 static void require(boolean value,String reason){if(!value)throw new AssertionError(reason);}

 static void run(JSONObject pair) throws Exception {
  long received=1_800_000_000_000L;
  JSONObject payload=PhoneCodeDelivery.manualPayload(pair,"012345",received,"manual-fixture-1");
  require(payload.length()==5,"Manual SMS payload fields changed");
  require("manual-fixture-1".equals(payload.getString("id")),"Manual delivery id changed");
  require(pair.getString("sender").equals(payload.getString("sender")),"Manual sender changed");
  require(pair.getString("recipient").equals(payload.getString("recipient")),"Manual recipient changed");
  require(pair.getString("template").replace("{code}","012345").equals(payload.getString("body")),"Manual code escaped the reviewed template");
  require(payload.getDouble("received_at")==received/1000.0,"Manual receipt time changed");

  for(String code:new String[]{null,"","12345","1234567","12A456","１２３４５６"," 123456","123456 "}){
   boolean refused=false;
   try{PhoneCodeDelivery.manualPayload(pair,code,received,"manual-fixture-invalid");}
   catch(IllegalArgumentException expected){refused=true;}
   require(refused,"Malformed manual login code accepted");
  }
  boolean refused=false;
  try{PhoneCodeDelivery.manualPayload(pair,"123456",received,"");}
  catch(IllegalArgumentException expected){refused=true;}
  require(refused,"Empty manual delivery id accepted");

  JSONObject ambiguous=new JSONObject(pair.toString());ambiguous.put("template",pair.getString("template")+" {code}");
  refused=false;
  try{PhoneCodeDelivery.manualPayload(ambiguous,"123456",received,"manual-fixture-ambiguous");}
  catch(Exception expected){refused=true;}
  require(refused,"Ambiguous manual code template accepted");
 }
}
