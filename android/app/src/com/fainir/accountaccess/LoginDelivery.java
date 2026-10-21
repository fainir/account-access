package com.fainir.accountaccess;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

/** Bounded delivery of the same login message after a transient network loss. */
final class LoginDelivery {
 interface Attempt { int send() throws IOException; }
 interface Gate { boolean allowed() throws Exception; }
 interface Sleeper { void pause(long millis) throws InterruptedException; }
 interface Status { void record(String value); }

 static boolean send(Attempt attempt, Gate gate, Sleeper sleeper, Status status) throws Exception {
  try {
   for(int index=0;index<30;index++) {
    if(Thread.currentThread().isInterrupted())throw new InterruptedException();
    if(!gate.allowed())return false;
    try {
     int response=attempt.send();
     if(response==200)return true;
     // A server refusal is not a Wi-Fi fault. In particular, never keep
     // presenting a revoked pairing token after an authorization failure.
     status.record("http_"+response);
     return false;
    } catch(SocketTimeoutException | SocketException | EOFException | UnknownHostException error) {
     status.record("link_error_"+error.getClass().getSimpleName());
    }
    // SSL/certificate/protocol errors and other unexpected failures propagate
    // without retry; all attempts keep the original pinned transport.
    if(index<29)sleeper.pause(1000);
   }
   return false;
  } catch(InterruptedException interrupted) {
   Thread.currentThread().interrupt();
   throw interrupted;
  }
 }
}
