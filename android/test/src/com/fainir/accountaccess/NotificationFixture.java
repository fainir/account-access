package com.fainir.accountaccess;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Test APK only: posts as its own UID. Exported entrypoint is shell-permission protected. */
public final class NotificationFixture extends BroadcastReceiver {
 @Override public void onReceive(Context context, Intent intent) {
  NotificationManager manager = context.getSystemService(NotificationManager.class);
  if (intent.getBooleanExtra("cancel", false)) {
   manager.cancel("account-access-fixture", 8);
   return;
  }
  String sender = intent.getStringExtra("sender");
  String body = intent.getStringExtra("body");
  if (sender == null || body == null || sender.length() > 200 || body.length() > 2000) return;
  manager.createNotificationChannel(new NotificationChannel("account-access-check",
    "Example login code", NotificationManager.IMPORTANCE_HIGH));
  manager.notify("account-access-fixture", 8, new Notification.Builder(context, "account-access-check")
    .setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(sender).setContentText(body)
    .setStyle(new Notification.BigTextStyle().bigText(body)).build());
 }
}
