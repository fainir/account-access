package com.fainir.accountaccess;

import android.app.Activity;
import android.companion.AssociationInfo;
import android.companion.AssociationRequest;
import android.companion.CompanionDeviceManager;
import android.companion.BluetoothLeDeviceFilter;
import android.bluetooth.le.ScanFilter;
import android.content.ComponentName;
import android.content.Context;
import android.content.IntentSender;
import android.os.Build;
import android.os.ParcelUuid;
import android.service.notification.NotificationListenerService;
import org.json.JSONArray;
import org.json.JSONObject;
import java.security.MessageDigest;

/** Android consent for the computer already selected by the local pairing QR. */
final class ComputerAssociation {
 static final int REQUEST = 11;
 private static volatile long generation;
 interface Update { void show(String message); }

 static boolean required() { return Build.VERSION.SDK_INT >= 35; }

 // A binding to every scoped pairing field, never a saved token or phone number.
 static String binding(JSONObject pair) throws Exception {
  JSONArray fields = new JSONArray();
  for (String key : new String[]{"url", "certificate_sha256", "source", "token", "sender", "recipient", "template", "bluetooth_service_uuid"}) {
   fields.put(pair.getString(key));
  }
  return LoginNotifications.hex(MessageDigest.getInstance("SHA-256").digest(fields.toString().getBytes("UTF-8")));
 }

 static boolean ready(Context context) {
  if (!required()) return true;
  try {
   JSONObject pair = Pairing.load(context);
   android.content.SharedPreferences saved = context.getSharedPreferences("computer_association", 0);
   if (pair == null || !binding(pair).equals(saved.getString("binding", ""))) return false;
   int id = saved.getInt("id", -1);
   CompanionDeviceManager manager = context.getSystemService(CompanionDeviceManager.class);
   if (manager == null) return false;
   for (AssociationInfo info : manager.getMyAssociations()) {
    if (info.getId() == id && !info.isSelfManaged() && info.getDeviceProfile() == null) return true;
   }
  } catch (Exception ignored) { }
  return false;
 }

 /** Invalidate local permission first, even if Android's service is unavailable. */
 static void clear(Context context) throws Exception {
  if (!required()) return;
  synchronized (Pairing.class) { generation++; }
  if (!context.getSharedPreferences("computer_association", 0).edit().clear().commit()) {
   throw new Exception("Could not clear computer permission");
  }
  CompanionDeviceManager manager = context.getSystemService(CompanionDeviceManager.class);
  if (manager == null) throw new Exception("Computer setup unavailable");
  // The app supports one computer. These are only this app's associations.
  for (AssociationInfo info : manager.getMyAssociations()) manager.disassociate(info.getId());
 }

 static void request(Activity activity, Update update) {
  if (!required()) return;
  try {
   JSONObject pair = Pairing.load(activity);
   if (pair == null) { update.show("Scan your computer's pairing QR first."); return; }
   if (!pair.has("bluetooth_service_uuid")) {
    update.show("Create a new pairing QR in an updated Account Access Mac app. Android needs Bluetooth discovery for this computer.");
    return;
   }
   if (ready(activity)) { update.show("Computer already connected with Android."); return; }
   final String expected = binding(pair);
   clear(activity);
   final long requestedGeneration = generation;
   CompanionDeviceManager manager = activity.getSystemService(CompanionDeviceManager.class);
   // Ordinary BLE discovery needs no privileged self-managed/computer/watch role.
   // The single scanned service is a fresh UUID from this Mac's pairing QR.
   BluetoothLeDeviceFilter device = new BluetoothLeDeviceFilter.Builder()
     .setScanFilter(new ScanFilter.Builder().setServiceUuid(
       ParcelUuid.fromString(pair.getString("bluetooth_service_uuid"))).build()).build();
   AssociationRequest request = new AssociationRequest.Builder()
     .addDeviceFilter(device).setSingleDevice(true).build();
   manager.associate(request, activity.getMainExecutor(), new CompanionDeviceManager.Callback() {
    @Override public void onAssociationPending(IntentSender consent) {
     try {
      if (activity.isDestroyed() || requestedGeneration != generation) return;
      activity.startIntentSenderForResult(consent, REQUEST, null, 0, 0, 0);
     }
     catch (Exception ignored) { update.show("Android computer permission was not completed. Try again."); }
    }
    @Override public void onAssociationCreated(AssociationInfo info) {
     synchronized (Pairing.class) {
     try {
      JSONObject current = Pairing.load(activity);
      if (activity.isDestroyed() || requestedGeneration != generation
          || current == null || !expected.equals(binding(current))
          || info.isSelfManaged() || info.getDeviceProfile() != null) {
       manager.disassociate(info.getId());
       update.show("Pairing changed. Connect the current computer again.");
       return;
      }
      if (!activity.getSharedPreferences("computer_association", 0).edit()
          .putInt("id", info.getId()).putString("binding", expected).commit()) {
       manager.disassociate(info.getId());
       update.show("Computer permission could not be saved. Try again.");
       return;
      }
      // Refresh Android's trust cache if access predates this association.
      // Missing notification access is expected here; it is granted separately.
      try {
       ComponentName listener = new ComponentName(activity, LoginNotifications.class);
       NotificationListenerService.requestUnbind(listener);
       NotificationListenerService.requestRebind(listener);
      } catch (Exception notGranted) { }
      update.show("Computer connected with Android. Enable login notification access next.");
     } catch (Exception ignored) {
      try { manager.disassociate(info.getId()); } catch (Exception unavailable) { }
      update.show("Computer permission could not be completed. Try again.");
     }
     }
    }
    @Override public void onFailure(CharSequence ignored) {
     update.show("Android computer permission was not granted. You can try again.");
    }
   });
  } catch (Exception ignored) {
   update.show("Android computer setup is unavailable. Reopen the app and try again.");
  }
 }
}
