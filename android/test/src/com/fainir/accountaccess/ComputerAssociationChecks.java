package com.fainir.accountaccess;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.Instrumentation;
import android.companion.CompanionDeviceManager;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityNodeInfo;
import java.util.concurrent.atomic.AtomicBoolean;

/** Uses real Android consent UI on a disposable emulator, never a shell role grant. */
final class ComputerAssociationChecks {
 static void run(Instrumentation test, String pairing) throws Exception {
  if (!ComputerAssociation.required()) return;
  Context context = test.getTargetContext();
  if (ComputerAssociation.ready(context)) throw new Exception("Unapproved computer accepted");
  AccessibilityServiceInfo info = test.getUiAutomation().getServiceInfo();
  info.flags |= AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
  test.getUiAutomation().setServiceInfo(info);
  MainActivity activity = (MainActivity)test.startActivitySync(
    new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
  consent(test, activity, false);
  if (ComputerAssociation.ready(context)) throw new Exception("Cancelled computer accepted");
  consent(test, activity, true);
  if (!ComputerAssociation.ready(context)) throw new Exception("Approved computer unavailable");
  CompanionDeviceManager manager = context.getSystemService(CompanionDeviceManager.class);
  for (android.companion.AssociationInfo association : manager.getMyAssociations()) {
   manager.disassociate(association.getId());
  }
  if (ComputerAssociation.ready(context)) throw new Exception("Revoked computer accepted");
  consent(test, activity, true);
  Pairing.save(context, pairing);
  if (ComputerAssociation.ready(context) || !manager.getMyAssociations().isEmpty()) {
   throw new Exception("Pairing replacement retained computer permission");
  }
  consent(test, activity, true);
  Pairing.clear(context);
  if (ComputerAssociation.ready(context) || !manager.getMyAssociations().isEmpty()) {
   throw new Exception("Disconnect retained computer permission");
  }
  Pairing.save(context, pairing);
  consent(test, activity, true);
 }

 static void consent(Instrumentation test, MainActivity activity, boolean accept) throws Exception {
  AtomicBoolean completed = new AtomicBoolean(false);
  test.runOnMainSync(() -> ComputerAssociation.request(activity, message -> completed.set(true)));
  String id = "com.android.companiondevicemanager:id/" + (accept ? "btn_positive" : "btn_negative");
  long deadline = SystemClock.elapsedRealtime() + 10000;
  boolean clicked = false;
  while (!clicked && SystemClock.elapsedRealtime() < deadline) {
   AccessibilityNodeInfo root = test.getUiAutomation().getRootInActiveWindow();
   if (root != null) {
    for (AccessibilityNodeInfo node : root.findAccessibilityNodeInfosByViewId(id)) {
     if (node.isVisibleToUser() && node.isEnabled()) {
      clicked = node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
      if (clicked) break;
     }
    }
   }
   if (!clicked) Thread.sleep(100);
  }
  if (!clicked) throw new Exception("Android computer consent button unavailable");
  deadline = SystemClock.elapsedRealtime() + 10000;
  while (!completed.get() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(100);
  if (!completed.get()) throw new Exception("Android computer consent did not finish");
  test.waitForIdleSync();
 }
}
