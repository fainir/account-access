package com.fainir.accountaccess;

import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.ProtocolException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;

/** Network recovery checks also run inside the notification/browser journey. */
final class LoginDeliveryChecks {
 static void require(boolean value, String reason) {
  if(!value)throw new AssertionError(reason);
 }

 static void run() throws Exception {
  int[] calls={0};
  ArrayList<Long> waits=new ArrayList<>();
  ArrayList<String> statuses=new ArrayList<>();
  boolean delivered=LoginDelivery.send(()->{
   if(++calls[0]==1)throw new SocketTimeoutException("fictional timeout");
   if(calls[0]==2)throw new ConnectException("fictional Wi-Fi disconnect");
   return 200;
  },()->true,waits::add,statuses::add);
  require(delivered && calls[0]==3 && waits.size()==2,"Wi-Fi recovery lost the original notification");
  require(waits.get(0)==1000 && waits.get(1)==1000,"Network retry did not back off");

  for(IOException failure:new IOException[]{new SocketException(),new EOFException(),new UnknownHostException()}) {
   calls[0]=0;
   delivered=LoginDelivery.send(()->{if(++calls[0]==1)throw failure;return 200;},()->true,value->{},value->{});
   require(delivered && calls[0]==2,"Eligible transient transport was not retried");
  }

  SSLHandshakeException certificateFailure=new SSLHandshakeException("fictional pin mismatch");
  certificateFailure.initCause(new SocketTimeoutException());
  for(IOException failure:new IOException[]{certificateFailure,new SSLProtocolException("fictional TLS protocol error"),new ProtocolException(),new IOException()}) {
   calls[0]=0;waits.clear();
   try {
    LoginDelivery.send(()->{calls[0]++;throw failure;},()->true,waits::add,value->{});
    throw new AssertionError("Security/protocol failure was swallowed");
   }catch(IOException actual){require(actual==failure,"Transport failure identity changed");}
   require(calls[0]==1 && waits.isEmpty(),"Security/protocol failure was retried");
  }

  for(int refusal:new int[]{302,401,403,429,500}) {
   calls[0]=0;waits.clear();statuses.clear();
   delivered=LoginDelivery.send(()->{calls[0]++;return refusal;},()->true,waits::add,statuses::add);
   require(!delivered && calls[0]==1 && waits.isEmpty(),"Server refusal was retried");
   require(statuses.size()==1 && statuses.get(0).equals("http_"+refusal),"Refusal diagnostic changed");
  }

  calls[0]=0;
  delivered=LoginDelivery.send(()->{calls[0]++;return 200;},()->false,value->{},value->{});
  require(!delivered && calls[0]==0,"Expired or removed pairing reached the network");

  boolean[] allowed={true};calls[0]=0;waits.clear();
  delivered=LoginDelivery.send(()->{calls[0]++;throw new SocketTimeoutException();},()->allowed[0],value->{waits.add(value);allowed[0]=false;},value->{});
  require(!delivered && calls[0]==1 && waits.size()==1,"Revocation or expiry during backoff was ignored");

  calls[0]=0;waits.clear();
  delivered=LoginDelivery.send(()->{calls[0]++;throw new SocketTimeoutException();},()->true,waits::add,value->{});
  require(!delivered && calls[0]==30 && waits.size()==29,"Network retry budget was not bounded");

  calls[0]=0;
  try {
   LoginDelivery.send(()->{calls[0]++;throw new SocketTimeoutException();},()->true,value->{throw new InterruptedException();},value->{});
   throw new AssertionError("Shutdown interruption was swallowed");
  }catch(InterruptedException expected){require(Thread.currentThread().isInterrupted() && calls[0]==1,"Shutdown interruption was lost");}
  finally{Thread.interrupted();}

  calls[0]=0;Thread.currentThread().interrupt();
  try {
   LoginDelivery.send(()->{calls[0]++;return 200;},()->true,value->{},value->{});
   throw new AssertionError("Interrupted queue item was transmitted");
  }catch(InterruptedException expected){require(calls[0]==0 && Thread.currentThread().isInterrupted(),"Canceled delivery reached the network");}
  finally{Thread.interrupted();}
 }

 public static void main(String[] args) throws Exception {
  run();
  System.out.println("PASS: transient Wi-Fi recovery, terminal refusals, freshness/revocation gates, bounded retries and cancellation");
 }
}
