package com.fainir.accountaccess;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;

/** An emulator without a real advertising Mac cannot qualify positive pairing. */
final class ComputerAssociationChecks {
 static boolean run(Instrumentation test, String pairing) throws Exception {
  if (!ComputerAssociation.required()) return false;
  Context context = test.getTargetContext();
  if (context.checkSelfPermission("android.permission.REQUEST_COMPANION_SELF_MANAGED")
      == PackageManager.PERMISSION_GRANTED) throw new Exception("Unexpected privileged permission");
  if (ComputerAssociation.ready(context)) throw new Exception("Unapproved computer accepted");
  MainActivity activity = (MainActivity)test.startActivitySync(
    new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
  AtomicReference<String> result = new AtomicReference<>();
  test.runOnMainSync(() -> ComputerAssociation.request(activity, result::set));
  if (result.get() == null || !result.get().startsWith("Create a new pairing QR")) {
   throw new Exception("Legacy QR did not require computer discovery");
  }
  JSONObject invalid = new JSONObject(pairing); invalid.put("bluetooth_service_uuid", "foreign-device");
  boolean rejected = false;
  try { Pairing.validate(invalid); } catch (Exception expected) { rejected = true; }
  if (!rejected) throw new Exception("Invalid discovery identity accepted");
  JSONObject candidate = new JSONObject(pairing);
  candidate.put("bluetooth_service_uuid", "e252e1a8-74ae-4fe5-8a8d-946742f51b4f");
  Pairing.save(context, candidate.toString());
  if (ComputerAssociation.ready(context)) throw new Exception("QR alone granted computer permission");
  Pairing.clear(context);
  if (ComputerAssociation.ready(context)) throw new Exception("Disconnected computer accepted");
  Pairing.save(context, candidate.toString());
  return true;
 }
}
