/* credentialtls.java */
/* Copyright (C) 2004 Pascal Urien (urienp@tele2.fr)
 * All rights reserved.
 *
 * This package is an implementation of the internet draft
 * "EAP support in smartcard" by Pascal Urien.
 * The implementation was written so as to conform with this draft.
 * 
 * This package is free for non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution.
 * 
 * Copyright remains Pascal Urien's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Pascal Urien should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes EAP-Smartcard software written by
 *     Pascal Urien (urienp@tele2.fr)"
 * 
 * THIS SOFTWARE IS PROVIDED BY PASCAL URIEN ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
 
 
/****************************************************************************************************************************
 | UPDATE 2011 - Gilles Bernabé                                                                                             |
 |--------------------------------------------------------------------------------------------------------------------------|
 | - remove cypher suite TLS_RSA_WITH_RC4_128_SHA and implementation of TLS_RSA_WITH_AES_128_CBC_SHA                        |
 | - implementation of the entire TLS Record and possibility to transmit the password from smart card to server through TLS |
 | - update RSA 1024 to RSA 2048 for client signature and encryption with server public key                                 |
 | - minor changes: memory management, harden certificate checking, cleanups...                                             |
 ****************************************************************************************************************************/

 
package applet;

import javacard.security.*;
import javacardx.crypto.*;

public class credentialtls {
	
	public MessageDigest       md5=null;
    public MessageDigest       sha=null;
    public RSAPrivateCrtKey    rsa_PrivateCrtKey=null;
    public RSAPublicKey        rsa_PublicKey=null;
	public RSAPublicKey        rsa_PublicKey_1024=null;
	public RSAPublicKey        rsa_PublicKey_2048=null;
	public RSAPublicKey        rsa_PublicKeyCA=null;
    public Cipher              cipherRSA=null;
    public RandomData          rnd=null ;
	
	public boolean test;
	public boolean step;
	public boolean enable_resume;
	
	public byte [] Cert;
	public short Cert_Offset, Cert_Length;
	
	// public  byte  [] PMK_Key;
    // public  short  PMK_Key_Offset, PMK_Key_Length;
	// public byte [] mastersecret;
	// public byte [] Certserver ;
	
}
    