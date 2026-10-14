package com.fainir.accountaccess;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.provider.Telephony;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;

public final class MainActivity extends Activity {
 TextView status;
 @Override public void onCreate(Bundle saved){super.onCreate(saved);show();}
 void show(){
  LinearLayout view=new LinearLayout(this);view.setOrientation(1);view.setPadding(32,48,32,24);setContentView(view);
  TextView heading=new TextView(this);heading.setText("Account Access Phone");heading.setTextSize(28);view.addView(heading);
  TextView explanation=new TextView(this);explanation.setText("Pair once with your computer. This companion checks notifications from your selected SMS app and forwards only matching fresh sign-in codes over encrypted private Wi-Fi. Android’s notification permission is broader than the filter; other notifications are discarded locally.");explanation.setTextSize(17);view.addView(explanation);
  status=new TextView(this);view.addView(status);refreshStatus();
  add(view,"Scan the pairing QR",()->startActivityForResult(new Intent(this,ScanActivity.class),10));
  EditText paste=new EditText(this);paste.setHint("Or paste pairing from your computer");paste.setInputType(129);view.addView(paste);
  add(view,"Use pasted pairing",()->{try{Pairing.save(this,paste.getText().toString());paste.setText("");refreshStatus();}catch(Exception e){status.setText("Pairing failed. Scan the QR from Account Access on your computer.");}});
  String defaultPackage=Telephony.Sms.getDefaultSmsPackage(this);
  getSharedPreferences("settings",0).edit().putString("sms_package",defaultPackage==null?"com.google.android.apps.messaging":defaultPackage).apply();
  TextView app=new TextView(this);app.setText("SMS app: "+getSharedPreferences("settings",0).getString("sms_package",""));view.addView(app);
  add(view,"Allow login notification access",()->startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)));
  add(view,"Disconnect phone",()->{Pairing.clear(this);refreshStatus();});
 }
 void add(LinearLayout view,String title,Runnable action){Button button=new Button(this);button.setText(title);button.setOnClickListener(v->action.run());view.addView(button);}
 void refreshStatus(){try{JSONObject pair=Pairing.load(this);status.setText(pair==null?"Not paired":"Paired for login messages from "+pair.getString("sender"));}catch(Exception e){status.setText("Reconnect your computer to repair pairing.");}}
 @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request==10&&result==RESULT_OK&&data!=null){try{Pairing.save(this,data.getStringExtra("pairing"));refreshStatus();}catch(Exception e){status.setText("This QR is not a valid Account Access pairing.");}}}
}
