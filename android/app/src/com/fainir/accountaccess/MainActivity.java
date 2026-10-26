package com.fainir.accountaccess;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.provider.Telephony;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;

public final class MainActivity extends Activity {
 TextView status;
 @Override public void onCreate(Bundle saved){super.onCreate(saved);show();}
 void show(){
  LinearLayout view=new LinearLayout(this);view.setOrientation(1);view.setPadding(32,48,32,24);ScrollView scroll=new ScrollView(this);scroll.addView(view);setContentView(scroll);
  TextView heading=new TextView(this);heading.setText("Account Access Phone");heading.setTextSize(28);view.addView(heading);
  TextView explanation=new TextView(this);explanation.setText("Pair once with your computer. This companion checks notifications from your selected SMS app and forwards only matching fresh sign-in codes over encrypted private Wi-Fi. Android’s notification permission is broader than the filter; other notifications are discarded locally.");explanation.setTextSize(17);view.addView(explanation);
  status=new TextView(this);view.addView(status);refreshStatus();
  add(view,"Scan the pairing QR",()->startActivityForResult(new Intent(this,ScanActivity.class),10));
  EditText paste=new EditText(this);paste.setHint("Or paste pairing from your computer");paste.setInputType(129);view.addView(paste);
  add(view,"Use pasted pairing",()->{try{Pairing.save(this,paste.getText().toString());paste.setText("");refreshStatus();}catch(Exception e){status.setText("Pairing failed. Scan the QR from Account Access on your computer.");}});
  if(ComputerAssociation.required()){
   TextView consent=new TextView(this);consent.setText("Keep the Mac pairing screen open and enable Bluetooth on both devices. Android discovers the computer from your QR and asks you to confirm it before sharing login notifications. The paired companion requests permission to run and deliver matching login messages in the background. Enable notification access afterwards. Disconnect removes this computer permission.");view.addView(consent);
   add(view,"Connect computer with Android",()->ComputerAssociation.request(this,message->status.setText(message)));
  }
  String defaultPackage=Telephony.Sms.getDefaultSmsPackage(this);
  if(!getSharedPreferences("settings",0).contains("sms_package"))getSharedPreferences("settings",0).edit().putString("sms_package",defaultPackage==null?"com.google.android.apps.messaging":defaultPackage).apply();
  TextView app=new TextView(this);app.setText("SMS app: "+getSharedPreferences("settings",0).getString("sms_package",""));view.addView(app);
  add(view,"Allow login notification access",()->{if(!ComputerAssociation.ready(this)){status.setText("Connect your paired computer with Android first.");return;}startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS));});
  add(view,"Disconnect phone",()->{try{Pairing.clear(this);refreshStatus();}catch(Exception e){status.setText("Disconnect could not finish. Check Android's connected-device permissions and try again.");}});
  add(view,"Open source licenses",this::showLicenses);
 }
 void showLicenses(){
  try(java.io.InputStream input=getAssets().open("THIRD_PARTY_NOTICES.txt");java.io.ByteArrayOutputStream text=new java.io.ByteArrayOutputStream()){
   byte[] block=new byte[4096];int size;while((size=input.read(block))!=-1){if(text.size()+size>65536)throw new java.io.IOException();text.write(block,0,size);}
   new android.app.AlertDialog.Builder(this).setTitle("Open source licenses").setMessage(new String(text.toByteArray(),"UTF-8")).setPositiveButton("Close",null).show();
  }catch(java.io.IOException unavailable){new android.app.AlertDialog.Builder(this).setTitle("Open source licenses").setMessage("The license notice could not be opened. Reinstall the verified app package to restore it.").setPositiveButton("Close",null).show();}
 }
 void add(LinearLayout view,String title,Runnable action){Button button=new Button(this);button.setText(title);button.setOnClickListener(v->action.run());view.addView(button);}
 void refreshStatus(){try{JSONObject pair=Pairing.load(this);status.setText(pair==null?"Not paired":!ComputerAssociation.ready(this)?"Pairing saved. Connect the computer with Android to receive login codes.":"Paired for login messages from "+pair.getString("sender"));}catch(Exception e){status.setText("Reconnect your computer to repair pairing.");}}
 @Override protected void onResume(){super.onResume();if(status!=null)refreshStatus();}
 @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request==10&&result==RESULT_OK&&data!=null){try{Pairing.save(this,data.getStringExtra("pairing"));refreshStatus();}catch(Exception e){status.setText("This QR is not a valid Account Access pairing.");}}}
}
