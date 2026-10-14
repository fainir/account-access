package com.fainir.accountaccess;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.*;
import android.media.Image;
import android.media.ImageReader;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.view.Surface;
import android.view.TextureView;
import java.nio.ByteBuffer;
import java.util.Arrays;
import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

public final class ScanActivity extends Activity implements TextureView.SurfaceTextureListener {
 TextureView texture;CameraDevice camera;CameraCaptureSession capture;ImageReader images;HandlerThread thread;Handler handler;volatile boolean found=false;boolean opening=false;
 @Override public void onCreate(Bundle state){super.onCreate(state);texture=new TextureView(this);texture.setSurfaceTextureListener(this);setContentView(texture);thread=new HandlerThread("pairing-camera");thread.start();handler=new Handler(thread.getLooper());if(checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.CAMERA},1);}
 @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] granted){super.onRequestPermissionsResult(request,permissions,granted);if(granted.length>0&&granted[0]==PackageManager.PERMISSION_GRANTED&&texture.isAvailable())open();else if(granted.length>0&&granted[0]!=PackageManager.PERMISSION_GRANTED)finish();}
 void open(){
  if(opening||found||checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED)return;opening=true;
  try{
   CameraManager manager=(CameraManager)getSystemService(CAMERA_SERVICE);String chosen=null;Size size=null;
   for(String id:manager.getCameraIdList()){CameraCharacteristics info=manager.getCameraCharacteristics(id);Integer facing=info.get(CameraCharacteristics.LENS_FACING);if(facing!=null&&facing==CameraCharacteristics.LENS_FACING_BACK){chosen=id;Size[] sizes=info.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP).getOutputSizes(ImageFormat.YUV_420_888);for(Size s:sizes)if(s.getWidth()<=1280&&(size==null||s.getWidth()>size.getWidth()))size=s;if(size==null)size=sizes[0];break;}}
   if(chosen==null||size==null){finish();return;}
   images=ImageReader.newInstance(size.getWidth(),size.getHeight(),ImageFormat.YUV_420_888,2);images.setOnImageAvailableListener(reader->decode(reader),handler);
   texture.getSurfaceTexture().setDefaultBufferSize(size.getWidth(),size.getHeight());
   manager.openCamera(chosen,new CameraDevice.StateCallback(){public void onOpened(CameraDevice device){camera=device;try{Surface preview=new Surface(texture.getSurfaceTexture());device.createCaptureSession(Arrays.asList(preview,images.getSurface()),new CameraCaptureSession.StateCallback(){public void onConfigured(CameraCaptureSession session){capture=session;try{CaptureRequest.Builder request=device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);request.addTarget(preview);request.addTarget(images.getSurface());request.set(CaptureRequest.CONTROL_AF_MODE,CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);session.setRepeatingRequest(request.build(),null,handler);}catch(Exception e){finish();}}public void onConfigureFailed(CameraCaptureSession session){finish();}},handler);}catch(Exception e){finish();}}public void onDisconnected(CameraDevice device){device.close();finish();}public void onError(CameraDevice device,int error){device.close();finish();}},handler);
  }catch(Exception e){finish();}
 }
 void decode(ImageReader reader){
  try(Image image=reader.acquireLatestImage()){
   if(image==null||found)return;Image.Plane plane=image.getPlanes()[0];ByteBuffer buffer=plane.getBuffer();int width=image.getWidth(),height=image.getHeight();byte[] pixels=new byte[width*height];for(int y=0;y<height;y++)for(int x=0;x<width;x++)pixels[y*width+x]=buffer.get(y*plane.getRowStride()+x*plane.getPixelStride());
   Result result=new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(new PlanarYUVLuminanceSource(pixels,width,height,0,0,width,height,false))));
   org.json.JSONObject object=new org.json.JSONObject(result.getText());Pairing.validate(object);found=true;runOnUiThread(()->{setResult(RESULT_OK,new Intent().putExtra("pairing",object.toString()));finish();});
  }catch(Exception ignored){}
 }
 @Override public void onSurfaceTextureAvailable(SurfaceTexture s,int width,int height){open();}public void onSurfaceTextureSizeChanged(SurfaceTexture s,int width,int height){}public boolean onSurfaceTextureDestroyed(SurfaceTexture s){return true;}public void onSurfaceTextureUpdated(SurfaceTexture s){}
 @Override protected void onDestroy(){if(capture!=null)capture.close();if(camera!=null)camera.close();if(images!=null)images.close();if(thread!=null)thread.quitSafely();super.onDestroy();}
}
