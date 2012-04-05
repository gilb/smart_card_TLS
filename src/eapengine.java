/* EapEngine.java */
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

package openeapsmartcard ;

import  javacard.framework.*;
import  javacard.security.* ;
import  javacardx.crypto.*;


/**
 * EAP Packet Processing
 */

public class eapengine extends Applet 
{   
  private static final  byte KEY_TYPE_SYMETRIC           = (byte) 0 ;
  private static final  byte KEY_TYPE_PMK                = (byte) 1 ;
  private static final  byte KEY_TYPE_RSA_PRIVATE_CRT    = (byte) 2 ;
  private static final  byte KEY_TYPE_RSA_PRIVATE        = (byte) 3 ;
  private static final  byte KEY_TYPE_RSA_PUBLIC         = (byte) 4 ;
  private static final  byte KEY_TYPE_RSA_PUBLIC_CA      = (byte) 5 ;
  private static final  byte KEY_TYPE_RSA_PRIVATE_CRT_DECRYPT    = (byte) 6 ;
  private static final  byte KEY_TYPE_RSA_CERT                   = (byte) 10 ;
  private static final  byte KEY_TYPE_ID                         = (byte) 10 ;
  
  
  private static final  byte EAP_TYPE_IDENTITY = (byte)1 ;
  private static final  byte EAP_TYPE_NAK      = (byte)3 ;
  private static final  byte EAP_TYPE_MD5      = (byte)4 ;
  private static final  byte EAP_TYPE_SHA1     = (byte)7 ;
  private static final  byte EAP_TYPE_PASSWORD = (byte)20;
  private static final  byte EAP_TYPE_TLS      = (byte)13;
  private static final  byte EAP_TYPE_PSK      = (byte)255;
  
  
  private  final static short   NVR_Size = (short)4096 ;  // Size of EAP Records Array
  public   static byte[]  NVR = null        ; 
	
  public   static byte[]  NVR_Test={
							 (byte)0,  // Alias-Type
							 (byte)1,  // Alias Length
							 (byte)'a',// Alias Value		  
							 (byte)9,  // EAP-ID Length (1 byte)
							 (byte)'a',(byte)'@',(byte)'d',(byte)'o',(byte)'t', // EAP-ID Value
							 (byte)'.',(byte)'c',(byte)'o',(byte)'m', 
							 EAP_TYPE_MD5, // EAP-Type
							 (byte)1, // Number of Keys
							 KEY_TYPE_SYMETRIC, // Key type
							 (byte)0,(byte)4, // Key Length (2 byte msb lsb)
							 (byte)'a',(byte)'b',(byte)'c',(byte)'d',// Key Value
							 (byte)0, // Alias-Type
							 (byte)4, // Alias Length
							 (byte)'t',(byte)'e',(byte)'s',(byte)'t',// Alias Value
							 (byte)4,   // EAP-ID Length
							 (byte)'m',(byte)'a',(byte)'r',(byte)'c', // EAP-ID
					  	     EAP_TYPE_SHA1, //EAP-Type
							 (byte)1,  // Number ok Keys
							 KEY_TYPE_SYMETRIC, // Key type
							 (byte)0,(byte)4, // Key Length
							 (byte)'m',(byte)'a',(byte)'r',(byte)'c', // Key Value
							 (byte)0, // Alias Type
							 (byte)1, // Alias Length
							 (byte)'c',	// Alias Value	 
							 (byte)9, // EAP-ID Length
							 (byte)'c',(byte)'@',(byte)'d',(byte)'o',(byte)'t',
					  	     (byte)'.',(byte)'c',(byte)'o',(byte)'m', // EAP-ID Value
							 EAP_TYPE_PASSWORD, // EAP-Type
							 (byte)1,  // Number of keys
							 KEY_TYPE_SYMETRIC, // Key type
							 (byte)0,(byte)8, // Key Length
							 (byte)'P',(byte)'A',(byte)'S',(byte)'S',(byte)'W',
							 (byte)'O',(byte)'R',(byte)'D', // Key Value
							 (byte)0, // Alias-Type
							 (byte)4, // Alias Length
							 (byte)'m',(byte)'a',(byte)'r',(byte)'c', // Alias Value						   
							 (byte)4, // EAP-ID Length
							 (byte)'m',(byte)'a',(byte)'r',(byte)'c', // EAP-ID Value
							 EAP_TYPE_SHA1, // EAP-Type
							 (byte)2, // Number of Keys
							 KEY_TYPE_SYMETRIC, // Key type
							 (byte)0,(byte)4, // Key Length
							 (byte)'m',(byte)'a',(byte)'r',(byte)'c', // Key Value
							 KEY_TYPE_PMK, // Key type
							 (byte)0,(byte)64, // Key Length
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
                             (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
                             (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0, // Alias-Type
							 (byte)3, // Alias Length
							 (byte)'a',(byte)'b',(byte)'c', // Alias Value						   
							 (byte)4, // EAP-ID Length
							 (byte)'a',(byte)'b',(byte)'c',(byte)'d', // EAP-ID Value
							  EAP_TYPE_TLS, // EAP-Type
							 (byte)4, // Number of Keys
							  KEY_TYPE_PMK, // Key type
							 (byte)0,(byte)80, // Key Length
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
                             (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
                             (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							  KEY_TYPE_RSA_PRIVATE_CRT,
							  (byte)1,(byte)74,
       (byte)0,(byte)64, // Q
	   (byte)0xe1,(byte)0xd9,(byte)0x6b,(byte)0x5e,(byte)0x41,(byte)0x2d,(byte)0x3e,(byte)0xb9,(byte)0x2a,(byte)0xa8,(byte)0x6b,(byte)0x6e,(byte)0xd0,(byte)0xfc,
       (byte)0xaa,(byte)0xb1,(byte)0xdf,(byte)0xa7,(byte)0x4e,(byte)0x90,(byte)0x8d,(byte)0x11,(byte)0x54,(byte)0x7c,(byte)0x0d,(byte)0xea,(byte)0x64,(byte)0xd5,(byte)0xf5,
       (byte)0xc1,(byte)0xd1,(byte)0x2b,(byte)0x02,(byte)0x77,(byte)0xb2,(byte)0xd2,(byte)0x6e,(byte)0xd8,(byte)0x93,(byte)0x56,(byte)0xad,(byte)0xee,(byte)0xca,(byte)0x5a,
       (byte)0xc0,(byte)0x92,(byte)0x64,(byte)0x4b,(byte)0xb8,(byte)0xd8,(byte)0xf4,(byte)0xa2,(byte)0x8c,(byte)0xf0,(byte)0x18,(byte)0x17,(byte)0x64,(byte)0x51,(byte)0x0b,
       (byte)0xdb,(byte)0x04,(byte)0xf3,(byte)0x3b,(byte)0x39,	
	  (byte)0,(byte)64, // P
	   (byte)0xfc,(byte)0x30,(byte)0xc8,(byte)0x10,(byte)0x41,(byte)0x80,(byte)0xf7,(byte)0xf2,(byte)0x1a,(byte)0x0c,(byte)0x28,(byte)0x2b,(byte)0x58,(byte)0xa0,       (byte)0x44,(byte)0x3e,(byte)0x01,(byte)0x13,(byte)0x91,(byte)0x66,(byte)0x4f,(byte)0x96,(byte)0x27,(byte)0x0e,(byte)0xc3,(byte)0x0a,(byte)0x4f,(byte)0x58,(byte)0xb5,       (byte)0x73,(byte)0x9a,(byte)0x3c,(byte)0x7a,(byte)0xfa,(byte)0xb9,(byte)0x19,(byte)0x8f,(byte)0x2b,(byte)0x32,(byte)0x8b,(byte)0xc8,(byte)0xbf,(byte)0x6c,(byte)0x77,       (byte)0xb3,(byte)0x4d,(byte)0xe5,(byte)0x71,(byte)0x80,(byte)0xe5,(byte)0x74,(byte)0x9a,(byte)0x76,(byte)0xa5,(byte)0xc0,(byte)0x41,(byte)0x14,(byte)0x81,(byte)0x76,       (byte)0xe0,(byte)0x9b,(byte)0x46,(byte)0xbd,(byte)0xdb,						 
	  (byte)0,(byte)64, // PQ
      (byte)0x5f,(byte)0x88,(byte)0x21,(byte)0x11,(byte)0x1f,(byte)0x0d,(byte)0xf0,(byte)0xcd,(byte)0x56,(byte)0x47,(byte)0x4f,(byte)0x1f,(byte)0x64,(byte)0x81,(byte)0x0e,
(byte)0xd1,(byte)0x02,(byte)0xeb,(byte)0x39,(byte)0x42,(byte)0x01,(byte)0xc7,(byte)0xe4,(byte)0x4b,(byte)0xb6,(byte)0x31,(byte)0x65,(byte)0x2a,(byte)0xfd,(byte)0x51,
(byte)0x11,(byte)0x1f,(byte)0xcd,(byte)0x3a,(byte)0x68,(byte)0xd4,(byte)0xe8,(byte)0x3c,(byte)0x4e,(byte)0x47,(byte)0xc1,(byte)0xce,(byte)0x76,(byte)0x6b,(byte)0x2b,
(byte)0x52,(byte)0xbd,(byte)0x76,(byte)0xdd,(byte)0x71,(byte)0x81,(byte)0x76,(byte)0x0f,(byte)0x69,(byte)0x9a,(byte)0x94,(byte)0xc3,(byte)0x41,(byte)0x3a,(byte)0x2e,
(byte)0xc9,(byte)0x47,(byte)0x3c,(byte)0xe5,
      (byte)0,(byte)64, // DQ1
      (byte)0x37,(byte)0x87,(byte)0x0e,(byte)0x27,(byte)0xd9,(byte)0x5c,(byte)0x77,(byte)0x6c,(byte)0x6d,(byte)0x39,(byte)0x85,(byte)0x58,(byte)0x74,(byte)0x97,(byte)0x7a,
(byte)0x9c,(byte)0x4b,(byte)0x01,(byte)0xc6,(byte)0x86,(byte)0x31,(byte)0xb8,(byte)0xce,(byte)0x0d,(byte)0xc6,(byte)0x1a,(byte)0x17,(byte)0xfa,(byte)0xa6,(byte)0xf6,
(byte)0xa5,(byte)0x27,(byte)0xae,(byte)0xee,(byte)0xa1,(byte)0x0f,(byte)0xad,(byte)0xe3,(byte)0x1f,(byte)0xae,(byte)0x93,(byte)0x0a,(byte)0xff,(byte)0xc3,(byte)0x7a,
(byte)0x4f,(byte)0x43,(byte)0xcb,(byte)0x7e,(byte)0x42,(byte)0x11,(byte)0x3b,(byte)0x99,(byte)0xed,(byte)0x39,(byte)0xef,(byte)0x1e,(byte)0x61,(byte)0xf2,(byte)0xc9,
(byte)0x41,(byte)0x99,(byte)0x4f,(byte)0xb9,
      (byte)0,(byte)64, // DP1
      (byte)0xdb,(byte)0x27,(byte)0xa9,(byte)0x34,(byte)0x37,(byte)0x38,(byte)0x54,(byte)0x3f,(byte)0xd7,(byte)0xd2,(byte)0xe8,(byte)0xb5,(byte)0x82,(byte)0x77,
(byte)0x03,(byte)0xd6,(byte)0xbe,(byte)0x28,(byte)0xbb,(byte)0x1a,(byte)0x25,(byte)0xdf,(byte)0x5e,(byte)0x61,(byte)0xbd,(byte)0xac,(byte)0x9f,(byte)0xf7,(byte)0x7e,
(byte)0xf7,(byte)0xce,(byte)0xf8,(byte)0xf0,(byte)0x06,(byte)0x22,(byte)0x04,(byte)0xcc,(byte)0x1d,(byte)0xc5,(byte)0xf7,(byte)0x23,(byte)0xa4,(byte)0xf6,(byte)0x25,
(byte)0xaf,(byte)0x73,(byte)0xea,(byte)0x08,(byte)0x10,(byte)0xf3,(byte)0x55,(byte)0xb9,(byte)0x45,(byte)0x92,(byte)0x14,(byte)0xd8,(byte)0x79,(byte)0x71,(byte)0x68,
(byte)0x55,(byte)0x17,(byte)0x9b,(byte)0x0a,(byte)0x31,
      KEY_TYPE_RSA_PUBLIC_CA,
	  (byte)1, (byte)7,
	  (byte)1,(byte)0,
	  (byte)0xa5,(byte)0x62,(byte)0xa0,(byte)0x41,(byte)0x52,(byte)0x9a,(byte)0xec,(byte)0x8e,
      (byte)0x27,(byte)0x24,(byte)0xa1,(byte)0x0c,(byte)0xa2,(byte)0x45,(byte)0x68,(byte)0xe3,
	  (byte)0xed,(byte)0xbd,(byte)0x3d,(byte)0x64,(byte)0x9a,(byte)0x7c,(byte)0xc2,(byte)0x74,
	  (byte)0x5a,(byte)0xe2,(byte)0x60,(byte)0xfa,(byte)0xac,(byte)0x6d,(byte)0x0f,(byte)0xdd,
	  (byte)0x4c,(byte)0x45,(byte)0xce,(byte)0x9d,(byte)0xb9,(byte)0x74,(byte)0x4e,(byte)0x35,
      (byte)0xfd,(byte)0x74,(byte)0xcd,(byte)0x13,(byte)0x63,(byte)0xdd,(byte)0xdc,(byte)0xce,
	  (byte)0x19,(byte)0x25,(byte)0xb9,(byte)0xd7,(byte)0x06,(byte)0x31,(byte)0x13,(byte)0xd7,
      (byte)0xea,(byte)0x1e,(byte)0x54,(byte)0x1a,(byte)0x07,(byte)0x36,(byte)0xeb,(byte)0x97,
	  (byte)0x2f,(byte)0x88,(byte)0x19,(byte)0x58,(byte)0xc5,(byte)0x76,(byte)0xec,(byte)0xf9,
      (byte)0xb3,(byte)0x71,(byte)0x66,(byte)0xfa,(byte)0x3a,(byte)0x4e,(byte)0x94,(byte)0xf9,
	  (byte)0x04,(byte)0x98,(byte)0xff,(byte)0xb0,(byte)0x7f,(byte)0xb0,(byte)0xdc,(byte)0xaf,
      (byte)0xc3,(byte)0xc8,(byte)0xa6,(byte)0x35,(byte)0x3d,(byte)0xab,(byte)0xd4,(byte)0x67,
	  (byte)0x07,(byte)0xff,(byte)0xc6,(byte)0xe8,(byte)0xf0,(byte)0x03,(byte)0xa5,(byte)0xf1,
      (byte)0x5b,(byte)0x00,(byte)0xc8,(byte)0x8f,(byte)0x36,(byte)0xa1,(byte)0xf3,(byte)0x88,
	  (byte)0xe8,(byte)0x23,(byte)0xf1,(byte)0x04,(byte)0xc6,(byte)0xd4,(byte)0x26,(byte)0xaf,
      (byte)0x37,(byte)0xad,(byte)0xa2,(byte)0x54,(byte)0x83,(byte)0xab,(byte)0x13,(byte)0x56,
	  (byte)0x83,(byte)0x8e,(byte)0x6f,(byte)0xb4,(byte)0x3a,(byte)0xd3,(byte)0x63,(byte)0x95,
      (byte)0x00,(byte)0xad,(byte)0xec,(byte)0x57,(byte)0x5d,(byte)0x95,(byte)0x2d,(byte)0x01,
	  (byte)0xf5,(byte)0x7b,(byte)0xae,(byte)0x6c,(byte)0xb6,(byte)0x43,(byte)0x4b,(byte)0xda,
      (byte)0x2b,(byte)0xe1,(byte)0xed,(byte)0xf4,(byte)0xab,(byte)0xe1,(byte)0x75,(byte)0x27,
	  (byte)0x0f,(byte)0x2e,(byte)0x06,(byte)0x5c,(byte)0x42,(byte)0x30,(byte)0xb4,(byte)0x5e,
      (byte)0x06,(byte)0x59,(byte)0x58,(byte)0xe4,(byte)0x4b,(byte)0xb6,(byte)0x0e,(byte)0xba,
	  (byte)0x71,(byte)0xd6,(byte)0x1c,(byte)0xa0,(byte)0x70,(byte)0xac,(byte)0xb1,(byte)0x2c,
      (byte)0xb2,(byte)0xfe,(byte)0x6b,(byte)0x7d,(byte)0xd8,(byte)0x42,(byte)0x1d,(byte)0x45,
	  (byte)0x9d,(byte)0xd5,(byte)0x4a,(byte)0x62,(byte)0x06,(byte)0x2e,(byte)0xe2,(byte)0xdc,
      (byte)0x88,(byte)0x5b,(byte)0x8b,(byte)0x72,(byte)0x45,(byte)0xac,(byte)0xe1,(byte)0x24,
	  (byte)0xea,(byte)0x08,(byte)0x66,(byte)0x30,(byte)0x5f,(byte)0x8c,(byte)0xe6,(byte)0x52,
      (byte)0x12,(byte)0x37,(byte)0x70,(byte)0x04,(byte)0xb0,(byte)0x37,(byte)0x5c,(byte)0x09,
	  (byte)0x1e,(byte)0x3b,(byte)0xd4,(byte)0x97,(byte)0x0c,(byte)0x9b,(byte)0x41,(byte)0x3f,
      (byte)0x86,(byte)0x08,(byte)0xd7,(byte)0xdb,(byte)0x19,(byte)0xcb,(byte)0x07,(byte)0xa3,
	  (byte)0xb9,(byte)0xcb,(byte)0x75,(byte)0x49,(byte)0x99,(byte)0xdc,(byte)0x20,(byte)0xcd,
      (byte)0xf0,(byte)0xdb,(byte)0x52,(byte)0x19,(byte)0x4b,(byte)0x15,(byte)0xf1,(byte)0x6d,
	  (byte)0,(byte)3,
      (byte)0x01, (byte)0x00, (byte)0x01,
	  KEY_TYPE_RSA_CERT,
	  (byte)0x05,(byte)0xdb,
	(byte)0x30,(byte)0x82,(byte)0x05,(byte)0xd7,(byte)0x30,(byte)0x82,(byte)0x04,(byte)0xbf,(byte)0xa0,(
byte)0x03,(byte)0x02,(byte)0x01,(byte)0x02,(byte)0x02,(byte)0x0a,(byte)0x61,
(byte)0x25,(byte)0x3d,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x06,(
byte)0x30,(byte)0x0d,(byte)0x06,(byte)0x09,(byte)0x2a,(byte)0x86,(byte)0x48,
(byte)0x86,(byte)0xf7,(byte)0x0d,(byte)0x01,(byte)0x01,(byte)0x05,(byte)0x05,(byte)0x00,(byte)0x30,(
byte)0x52,(byte)0x31,(byte)0x12,(byte)0x30,(byte)0x10,(byte)0x06,(byte)0x0a,
(byte)0x09,(byte)0x92,(byte)0x26,(byte)0x89,(byte)0x93,(byte)0xf2,(byte)0x2c,(byte)0x64,(byte)0x01,(
byte)0x19,(byte)0x16,(byte)0x02,(byte)0x66,(byte)0x72,(byte)0x31,(byte)0x14,
(byte)0x30,(byte)0x12,(byte)0x06,(byte)0x0a,(byte)0x09,(byte)0x92,(byte)0x26,(byte)0x89,(byte)0x93,(
byte)0xf2,(byte)0x2c,(byte)0x64,(byte)0x01,(byte)0x19,(byte)0x16,(byte)0x04,
(byte)0x65,(byte)0x6e,(byte)0x73,(byte)0x74,(byte)0x31,(byte)0x15,(byte)0x30,(byte)0x13,(byte)0x06,(
byte)0x0a,(byte)0x09,(byte)0x92,(byte)0x26,(byte)0x89,(byte)0x93,(byte)0xf2,
(byte)0x2c,(byte)0x64,(byte)0x01,(byte)0x19,(byte)0x16,(byte)0x05,(byte)0x62,(byte)0x61,(byte)0x64,(
byte)0x72,(byte)0x61,(byte)0x31,(byte)0x0f,(byte)0x30,(byte)0x0d,(byte)0x06,
(byte)0x03,(byte)0x55,(byte)0x04,(byte)0x03,(byte)0x13,(byte)0x06,(byte)0x63,(byte)0x61,(byte)0x77,(
byte)0x69,(byte)0x66,(byte)0x69,(byte)0x30,(byte)0x1e,(byte)0x17,(byte)0x0d,
(byte)0x30,(byte)0x33,(byte)0x31,(byte)0x31,(byte)0x30,(byte)0x36,(byte)0x30,(byte)0x39,(byte)0x33,(
byte)0x36,(byte)0x35,(byte)0x39,(byte)0x5a,(byte)0x17,(byte)0x0d,(byte)0x30,
(byte)0x34,(byte)0x31,(byte)0x31,(byte)0x30,(byte)0x35,(byte)0x30,(byte)0x39,(byte)0x33,(byte)0x36,(
byte)0x35,(byte)0x39,(byte)0x5a,(byte)0x30,(byte)0x62,(byte)0x31,(byte)0x12,
(byte)0x30,(byte)0x10,(byte)0x06,(byte)0x0a,(byte)0x09,(byte)0x92,(byte)0x26,(byte)0x89,(byte)0x93,(
byte)0xf2,(byte)0x2c,(byte)0x64,(byte)0x01,(byte)0x19,(byte)0x16,(byte)0x02,
(byte)0x66,(byte)0x72,(byte)0x31,(byte)0x14,(byte)0x30,(byte)0x12,(byte)0x06,(byte)0x0a,(byte)0x09,(
byte)0x92,(byte)0x26,(byte)0x89,(byte)0x93,(byte)0xf2,(byte)0x2c,(byte)0x64,
(byte)0x01,(byte)0x19,(byte)0x16,(byte)0x04,(byte)0x65,(byte)0x6e,(byte)0x73,(byte)0x74,(byte)0x31,(
byte)0x15,(byte)0x30,(byte)0x13,(byte)0x06,(byte)0x0a,(byte)0x09,(byte)0x92,
(byte)0x26,(byte)0x89,(byte)0x93,(byte)0xf2,(byte)0x2c,(byte)0x64,(byte)0x01,(byte)0x19,(byte)0x16,(
byte)0x05,(byte)0x62,(byte)0x61,(byte)0x64,(byte)0x72,(byte)0x61,(byte)0x31,
(byte)0x0e,(byte)0x30,(byte)0x0c,(byte)0x06,(byte)0x03,(byte)0x55,(byte)0x04,(byte)0x03,(byte)0x13,(
byte)0x05,(byte)0x55,(byte)0x73,(byte)0x65,(byte)0x72,(byte)0x73,(byte)0x31,
(byte)0x0f,(byte)0x30,(byte)0x0d,(byte)0x06,(byte)0x03,(byte)0x55,(byte)0x04,(byte)0x03,(byte)0x13,(
byte)0x06,(byte)0x68,(byte)0x61,(byte)0x6a,(byte)0x6a,(byte)0x65,(byte)0x68,
(byte)0x30,(byte)0x81,(byte)0x9f,(byte)0x30,(byte)0x0d,(byte)0x06,(byte)0x09,(byte)0x2a,(byte)0x86,(
byte)0x48,(byte)0x86,(byte)0xf7,(byte)0x0d,(byte)0x01,(byte)0x01,(byte)0x01,
(byte)0x05,(byte)0x00,(byte)0x03,(byte)0x81,(byte)0x8d,(byte)0x00,(byte)0x30,(byte)0x81,(byte)0x89,(
byte)0x02,(byte)0x81,(byte)0x81,(byte)0x00,(byte)0xde,(byte)0x7d,(byte)0x0e,
(byte)0xf5,(byte)0x1d,(byte)0x17,(byte)0x16,(byte)0xc0,(byte)0x6f,(byte)0x51,(byte)0xb0,(byte)0x4c,(
byte)0xef,(byte)0x2e,(byte)0xc6,(byte)0xca,(byte)0xf4,(byte)0xd8,(byte)0x66,
(byte)0x01,(byte)0xbc,(byte)0x7b,(byte)0x21,(byte)0x12,(byte)0x37,(byte)0xce,(byte)0xdc,(byte)0x61,(
byte)0x72,(byte)0xf3,(byte)0xc8,(byte)0xff,(byte)0x83,(byte)0x5c,(byte)0x2f,
(byte)0xf5,(byte)0x2b,(byte)0xf8,(byte)0xf0,(byte)0x0f,(byte)0xbd,(byte)0x89,(byte)0x86,(byte)0x6a,(
byte)0x3f,(byte)0xc2,(byte)0x8b,(byte)0x3b,(byte)0xbd,(byte)0xc7,(byte)0x98,
(byte)0xfd,(byte)0x4b,(byte)0x1d,(byte)0x67,(byte)0x8f,(byte)0x85,(byte)0x66,(byte)0x12,(byte)0x74,(
byte)0x6f,(byte)0x64,(byte)0x74,(byte)0xd0,(byte)0x31,(byte)0x07,(byte)0x46,
(byte)0x04,(byte)0xba,(byte)0xb1,(byte)0x74,(byte)0x70,(byte)0xb1,(byte)0xfc,(byte)0xd9,(byte)0x42,(
byte)0x44,(byte)0xf8,(byte)0x97,(byte)0xc2,(byte)0x74,(byte)0xb9,(byte)0x45,
(byte)0x5c,(byte)0x84,(byte)0x15,(byte)0x33,(byte)0xec,(byte)0x4a,(byte)0xcb,(byte)0x41,(byte)0xd2,(
byte)0x6e,(byte)0x7c,(byte)0x6d,(byte)0xbd,(byte)0xbc,(byte)0xcd,(byte)0x3e,
(byte)0x64,(byte)0xff,(byte)0x8f,(byte)0x33,(byte)0x63,(byte)0xfe,(byte)0x06,(byte)0x55,(byte)0x69,(
byte)0x96,(byte)0xc6,(byte)0x96,(byte)0xfa,(byte)0x17,(byte)0xdb,(byte)0xf8,
(byte)0x7f,(byte)0xeb,(byte)0x5b,(byte)0xfe,(byte)0x00,(byte)0x3e,(byte)0xd1,(byte)0x8e,(byte)0x42,(
byte)0x83,(byte)0x62,(byte)0xbe,(byte)0xc3,(byte)0x02,(byte)0x03,(byte)0x01,
(byte)0x00,(byte)0x01,(byte)0xa3,(byte)0x82,(byte)0x03,(byte)0x21,(byte)0x30,(byte)0x82,(byte)0x03,(
byte)0x1d,(byte)0x30,(byte)0x0b,(byte)0x06,(byte)0x03,(byte)0x55,(byte)0x1d,
(byte)0x0f,(byte)0x04,(byte)0x04,(byte)0x03,(byte)0x02,(byte)0x05,(byte)0xa0,(byte)0x30,(byte)0x44,(
byte)0x06,(byte)0x09,(byte)0x2a,(byte)0x86,(byte)0x48,(byte)0x86,(byte)0xf7,
(byte)0x0d,(byte)0x01,(byte)0x09,(byte)0x0f,(byte)0x04,(byte)0x37,(byte)0x30,(byte)0x35,(byte)0x30,(
byte)0x0e,(byte)0x06,(byte)0x08,(byte)0x2a,(byte)0x86,(byte)0x48,(byte)0x86,
(byte)0xf7,(byte)0x0d,(byte)0x03,(byte)0x02,(byte)0x02,(byte)0x02,(byte)0x00,(byte)0x80,(byte)0x30,(
byte)0x0e,(byte)0x06,(byte)0x08,(byte)0x2a,(byte)0x86,(byte)0x48,(byte)0x86,
(byte)0xf7,(byte)0x0d,(byte)0x03,(byte)0x04,(byte)0x02,(byte)0x02,(byte)0x00,(byte)0x80,(byte)0x30,(
byte)0x07,(byte)0x06,(byte)0x05,(byte)0x2b,(byte)0x0e,(byte)0x03,(byte)0x02,
(byte)0x07,(byte)0x30,(byte)0x0a,(byte)0x06,(byte)0x08,(byte)0x2a,(byte)0x86,(byte)0x48,(byte)0x86,(
byte)0xf7,(byte)0x0d,(byte)0x03,(byte)0x07,(byte)0x30,(byte)0x1d,(byte)0x06,
(byte)0x03,(byte)0x55,(byte)0x1d,(byte)0x0e,(byte)0x04,(byte)0x16,(byte)0x04,(byte)0x14,(byte)0x52,(
byte)0x6e,(byte)0x17,(byte)0x06,(byte)0x49,(byte)0x66,(byte)0x7e,(byte)0x12,
(byte)0xfd,(byte)0x1e,(byte)0xc6,(byte)0x9d,(byte)0x4c,(byte)0xc8,(byte)0xa0,(byte)0x26,(byte)0x40,(
byte)0xb7,(byte)0x59,(byte)0x28,(byte)0x30,(byte)0x17,(byte)0x06,(byte)0x09,
(byte)0x2b,(byte)0x06,(byte)0x01,(byte)0x04,(byte)0x01,(byte)0x82,(byte)0x37,(byte)0x14,(byte)0x02,(
byte)0x04,(byte)0x0a,(byte)0x1e,(byte)0x08,(byte)0x00,(byte)0x55,(byte)0x00,
(byte)0x73,(byte)0x00,(byte)0x65,(byte)0x00,(byte)0x72,(byte)0x30,(byte)0x1f,(byte)0x06,(byte)0x03,(
byte)0x55,(byte)0x1d,(byte)0x23,(byte)0x04,(byte)0x18,(byte)0x30,(byte)0x16,
(byte)0x80,(byte)0x14,(byte)0xe5,(byte)0x6d,(byte)0xc5,(byte)0x50,(byte)0x20,(byte)0x88,(byte)0x1e,(
byte)0x39,(byte)0x00,(byte)0x39,(byte)0x8a,(byte)0xf9,(byte)0x9e,(byte)0xe0,
(byte)0x78,(byte)0x9d,(byte)0xa4,(byte)0x23,(byte)0x0f,(byte)0x89,(byte)0x30,(byte)0x81,(byte)0xfb,(
byte)0x06,(byte)0x03,(byte)0x55,(byte)0x1d,(byte)0x1f,(byte)0x04,(byte)0x81,
(byte)0xf3,(byte)0x30,(byte)0x81,(byte)0xf0,(byte)0x30,(byte)0x81,(byte)0xed,(byte)0xa0,(byte)0x81,(
byte)0xea,(byte)0xa0,(byte)0x81,(byte)0xe7,(byte)0x86,(byte)0x81,(byte)0xb1,
(byte)0x6c,(byte)0x64,(byte)0x61,(byte)0x70,(byte)0x3a,(byte)0x2f,(byte)0x2f,(byte)0x2f,(byte)0x43,(
byte)0x4e,(byte)0x3d,(byte)0x63,(byte)0x61,(byte)0x77,(byte)0x69,(byte)0x66,
(byte)0x69,(byte)0x2c,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x61,(byte)0x6b,(byte)0x6b,(byte)0x61,(
byte)0x72,(byte)0x31,(byte)0x2c,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x43,
(byte)0x44,(byte)0x50,(byte)0x2c,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x50,(byte)0x75,(byte)0x62,(
byte)0x6c,(byte)0x69,(byte)0x63,(byte)0x25,(byte)0x32,(byte)0x30,(byte)0x4b,
(byte)0x65,(byte)0x79,(byte)0x25,(byte)0x32,(byte)0x30,(byte)0x53,(byte)0x65,(byte)0x72,(byte)0x76,(
byte)0x69,(byte)0x63,(byte)0x65,(byte)0x73,(byte)0x2c,(byte)0x43,(byte)0x4e,
(byte)0x3d,(byte)0x53,(byte)0x65,(byte)0x72,(byte)0x76,(byte)0x69,(byte)0x63,(byte)0x65,(byte)0x73,(
byte)0x2c,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x43,(byte)0x6f,(byte)0x6e,
(byte)0x66,(byte)0x69,(byte)0x67,(byte)0x75,(byte)0x72,(byte)0x61,(byte)0x74,(byte)0x69,(byte)0x6f,(
byte)0x6e,(byte)0x2c,(byte)0x44,(byte)0x43,(byte)0x3d,(byte)0x62,(byte)0x61,
(byte)0x64,(byte)0x72,(byte)0x61,(byte)0x2c,(byte)0x44,(byte)0x43,(byte)0x3d,(byte)0x65,(byte)0x6e,(
byte)0x73,(byte)0x74,(byte)0x2c,(byte)0x44,(byte)0x43,(byte)0x3d,(byte)0x66,
(byte)0x72,(byte)0x3f,(byte)0x63,(byte)0x65,(byte)0x72,(byte)0x74,(byte)0x69,(byte)0x66,(byte)0x69,(
byte)0x63,(byte)0x61,(byte)0x74,(byte)0x65,(byte)0x52,(byte)0x65,(byte)0x76,
(byte)0x6f,(byte)0x63,(byte)0x61,(byte)0x74,(byte)0x69,(byte)0x6f,(byte)0x6e,(byte)0x4c,(byte)0x69,(
byte)0x73,(byte)0x74,(byte)0x3f,(byte)0x62,(byte)0x61,(byte)0x73,(byte)0x65,
(byte)0x3f,(byte)0x6f,(byte)0x62,(byte)0x6a,(byte)0x65,(byte)0x63,(byte)0x74,(byte)0x43,(byte)0x6c,(
byte)0x61,(byte)0x73,(byte)0x73,(byte)0x3d,(byte)0x63,(byte)0x52,(byte)0x4c,
(byte)0x44,(byte)0x69,(byte)0x73,(byte)0x74,(byte)0x72,(byte)0x69,(byte)0x62,(byte)0x75,(byte)0x74,(
byte)0x69,(byte)0x6f,(byte)0x6e,(byte)0x50,(byte)0x6f,(byte)0x69,(byte)0x6e,
(byte)0x74,(byte)0x86,(byte)0x31,(byte)0x68,(byte)0x74,(byte)0x74,(byte)0x70,(byte)0x3a,(byte)0x2f,(
byte)0x2f,(byte)0x61,(byte)0x6b,(byte)0x6b,(byte)0x61,(byte)0x72,(byte)0x31,
(byte)0x2e,(byte)0x62,(byte)0x61,(byte)0x64,(byte)0x72,(byte)0x61,(byte)0x2e,(byte)0x65,(byte)0x6e,(
byte)0x73,(byte)0x74,(byte)0x2e,(byte)0x66,(byte)0x72,(byte)0x2f,(byte)0x43,
(byte)0x65,(byte)0x72,(byte)0x74,(byte)0x45,(byte)0x6e,(byte)0x72,(byte)0x6f,(byte)0x6c,(byte)0x6c,(
byte)0x2f,(byte)0x63,(byte)0x61,(byte)0x77,(byte)0x69,(byte)0x66,(byte)0x69,
(byte)0x2e,(byte)0x63,(byte)0x72,(byte)0x6c,(byte)0x30,(byte)0x82,(byte)0x01,(byte)0x13,(byte)0x06,(
byte)0x08,(byte)0x2b,(byte)0x06,(byte)0x01,(byte)0x05,(byte)0x05,(byte)0x07,
(byte)0x01,(byte)0x01,(byte)0x04,(byte)0x82,(byte)0x01,(byte)0x05,(byte)0x30,(byte)0x82,(byte)0x01,(
byte)0x01,(byte)0x30,(byte)0x81,(byte)0xaa,(byte)0x06,(byte)0x08,(byte)0x2b,
(byte)0x06,(byte)0x01,(byte)0x05,(byte)0x05,(byte)0x07,(byte)0x30,(byte)0x02,(byte)0x86,(byte)0x81,(
byte)0x9d,(byte)0x6c,(byte)0x64,(byte)0x61,(byte)0x70,(byte)0x3a,(byte)0x2f,
(byte)0x2f,(byte)0x2f,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x63,(byte)0x61,(byte)0x77,(byte)0x69,(
byte)0x66,(byte)0x69,(byte)0x2c,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x41,
(byte)0x49,(byte)0x41,(byte)0x2c,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x50,(byte)0x75,(byte)0x62,(
byte)0x6c,(byte)0x69,(byte)0x63,(byte)0x25,(byte)0x32,(byte)0x30,(byte)0x4b,
(byte)0x65,(byte)0x79,(byte)0x25,(byte)0x32,(byte)0x30,(byte)0x53,(byte)0x65,(byte)0x72,(byte)0x76,(
byte)0x69,(byte)0x63,(byte)0x65,(byte)0x73,(byte)0x2c,(byte)0x43,(byte)0x4e,
(byte)0x3d,(byte)0x53,(byte)0x65,(byte)0x72,(byte)0x76,(byte)0x69,(byte)0x63,(byte)0x65,(byte)0x73,(
byte)0x2c,(byte)0x43,(byte)0x4e,(byte)0x3d,(byte)0x43,(byte)0x6f,(byte)0x6e,
(byte)0x66,(byte)0x69,(byte)0x67,(byte)0x75,(byte)0x72,(byte)0x61,(byte)0x74,(byte)0x69,(byte)0x6f,(
byte)0x6e,(byte)0x2c,(byte)0x44,(byte)0x43,(byte)0x3d,(byte)0x62,(byte)0x61,
(byte)0x64,(byte)0x72,(byte)0x61,(byte)0x2c,(byte)0x44,(byte)0x43,(byte)0x3d,(byte)0x65,(byte)0x6e,(
byte)0x73,(byte)0x74,(byte)0x2c,(byte)0x44,(byte)0x43,(byte)0x3d,(byte)0x66,
(byte)0x72,(byte)0x3f,(byte)0x63,(byte)0x41,(byte)0x43,(byte)0x65,(byte)0x72,(byte)0x74,(byte)0x69,(
byte)0x66,(byte)0x69,(byte)0x63,(byte)0x61,(byte)0x74,(byte)0x65,(byte)0x3f,
(byte)0x62,(byte)0x61,(byte)0x73,(byte)0x65,(byte)0x3f,(byte)0x6f,(byte)0x62,(byte)0x6a,(byte)0x65,(
byte)0x63,(byte)0x74,(byte)0x43,(byte)0x6c,(byte)0x61,(byte)0x73,(byte)0x73,
(byte)0x3d,(byte)0x63,(byte)0x65,(byte)0x72,(byte)0x74,(byte)0x69,(byte)0x66,(byte)0x69,(byte)0x63,(
byte)0x61,(byte)0x74,(byte)0x69,(byte)0x6f,(byte)0x6e,(byte)0x41,(byte)0x75,
(byte)0x74,(byte)0x68,(byte)0x6f,(byte)0x72,(byte)0x69,(byte)0x74,(byte)0x79,(byte)0x30,(byte)0x52,(
byte)0x06,(byte)0x08,(byte)0x2b,(byte)0x06,(byte)0x01,(byte)0x05,(byte)0x05,
(byte)0x07,(byte)0x30,(byte)0x02,(byte)0x86,(byte)0x46,(byte)0x68,(byte)0x74,(byte)0x74,(byte)0x70,(
byte)0x3a,(byte)0x2f,(byte)0x2f,(byte)0x61,(byte)0x6b,(byte)0x6b,(byte)0x61,
(byte)0x72,(byte)0x31,(byte)0x2e,(byte)0x62,(byte)0x61,(byte)0x64,(byte)0x72,(byte)0x61,(byte)0x2e,(
byte)0x65,(byte)0x6e,(byte)0x73,(byte)0x74,(byte)0x2e,(byte)0x66,(byte)0x72,
(byte)0x2f,(byte)0x43,(byte)0x65,(byte)0x72,(byte)0x74,(byte)0x45,(byte)0x6e,(byte)0x72,(byte)0x6f,(
byte)0x6c,(byte)0x6c,(byte)0x2f,(byte)0x61,(byte)0x6b,(byte)0x6b,(byte)0x61,
(byte)0x72,(byte)0x31,(byte)0x2e,(byte)0x62,(byte)0x61,(byte)0x64,(byte)0x72,(byte)0x61,(byte)0x2e,(
byte)0x65,(byte)0x6e,(byte)0x73,(byte)0x74,(byte)0x2e,(byte)0x66,(byte)0x72,
(byte)0x5f,(byte)0x63,(byte)0x61,(byte)0x77,(byte)0x69,(byte)0x66,(byte)0x69,(byte)0x2e,(byte)0x63,(
byte)0x72,(byte)0x74,(byte)0x30,(byte)0x29,(byte)0x06,(byte)0x03,(byte)0x55,
(byte)0x1d,(byte)0x25,(byte)0x04,(byte)0x22,(byte)0x30,(byte)0x20,(byte)0x06,(byte)0x0a,(byte)0x2b,(
byte)0x06,(byte)0x01,(byte)0x04,(byte)0x01,(byte)0x82,(byte)0x37,(byte)0x0a,
(byte)0x03,(byte)0x04,(byte)0x06,(byte)0x08,(byte)0x2b,(byte)0x06,(byte)0x01,(byte)0x05,(byte)0x05,(
byte)0x07,(byte)0x03,(byte)0x04,(byte)0x06,(byte)0x08,(byte)0x2b,(byte)0x06,
(byte)0x01,(byte)0x05,(byte)0x05,(byte)0x07,(byte)0x03,(byte)0x02,(byte)0x30,(byte)0x2f,(byte)0x06,(
byte)0x03,(byte)0x55,(byte)0x1d,(byte)0x11,(byte)0x04,(byte)0x28,(byte)0x30,
(byte)0x26,(byte)0xa0,(byte)0x24,(byte)0x06,(byte)0x0a,(byte)0x2b,(byte)0x06,(byte)0x01,(byte)0x04,(
byte)0x01,(byte)0x82,(byte)0x37,(byte)0x14,(byte)0x02,(byte)0x03,(byte)0xa0,
(byte)0x16,(byte)0x0c,(byte)0x14,(byte)0x68,(byte)0x61,(byte)0x6a,(byte)0x6a,(byte)0x65,(byte)0x68,(
byte)0x40,(byte)0x62,(byte)0x61,(byte)0x64,(byte)0x72,(byte)0x61,(byte)0x2e,
(byte)0x65,(byte)0x6e,(byte)0x73,(byte)0x74,(byte)0x2e,(byte)0x66,(byte)0x72,(byte)0x30,(byte)0x0d,(
byte)0x06,(byte)0x09,(byte)0x2a,(byte)0x86,(byte)0x48,(byte)0x86,(byte)0xf7,
(byte)0x0d,(byte)0x01,(byte)0x01,(byte)0x05,(byte)0x05,(byte)0x00,(byte)0x03,(byte)0x82,(byte)0x01,(
byte)0x01,(byte)0x00,(byte)0x13,(byte)0xa2,(byte)0x33,(byte)0xaa,(byte)0x6e,
(byte)0xdb,(byte)0x42,(byte)0x82,(byte)0xa6,(byte)0x9e,(byte)0xf9,(byte)0xd0,(byte)0x23,(byte)0xd5,(
byte)0x1f,(byte)0x32,(byte)0xfd,(byte)0x0b,(byte)0x97,(byte)0xaf,(byte)0x03,
(byte)0xc4,(byte)0xba,(byte)0xcd,(byte)0x6b,(byte)0x7e,(byte)0xd5,(byte)0xc1,(byte)0x55,(byte)0x11,(
byte)0x0e,(byte)0xba,(byte)0xcc,(byte)0x3f,(byte)0x0f,(byte)0xad,(byte)0x6d,
(byte)0x85,(byte)0x3d,(byte)0xee,(byte)0x84,(byte)0x5c,(byte)0xc3,(byte)0x3d,(byte)0x0e,(byte)0x9d,(
byte)0x8e,(byte)0xcc,(byte)0x75,(byte)0x14,(byte)0x29,(byte)0x5f,(byte)0x85,
(byte)0x4d,(byte)0x16,(byte)0xf6,(byte)0x40,(byte)0x9d,(byte)0xfe,(byte)0xb6,(byte)0x1a,(byte)0x60,(
byte)0xc9,(byte)0xa1,(byte)0xef,(byte)0x0b,(byte)0xc0,(byte)0x9a,(byte)0xd3,
(byte)0xc1,(byte)0xa9,(byte)0x3b,(byte)0xee,(byte)0x54,(byte)0x6b,(byte)0x2d,(byte)0xf9,(byte)0xdb,(
byte)0xab,(byte)0x8a,(byte)0xd9,(byte)0xa9,(byte)0x0a,(byte)0xab,(byte)0x5c,
(byte)0xee,(byte)0x35,(byte)0xff,(byte)0x67,(byte)0x51,(byte)0x27,(byte)0x58,(byte)0x73,(byte)0xd1,(
byte)0xc5,(byte)0x09,(byte)0x33,(byte)0x39,(byte)0xb4,(byte)0xad,(byte)0xea,
(byte)0x0f,(byte)0x40,(byte)0xc5,(byte)0x47,(byte)0x54,(byte)0xda,(byte)0xe7,(byte)0x46,(byte)0x19,(
byte)0x66,(byte)0x32,(byte)0x2b,(byte)0x57,(byte)0x72,(byte)0xb4,(byte)0x60,
(byte)0xb7,(byte)0xfa,(byte)0x2f,(byte)0x59,(byte)0x85,(byte)0xd4,(byte)0x96,(byte)0xc5,(byte)0x2c,(
byte)0xaf,(byte)0x74,(byte)0x56,(byte)0xdf,(byte)0x2d,(byte)0x78,(byte)0xe4,
(byte)0xde,(byte)0x9b,(byte)0x1c,(byte)0x48,(byte)0xf2,(byte)0xac,(byte)0xb9,(byte)0x87,(byte)0xba,(
byte)0x9b,(byte)0xde,(byte)0x3d,(byte)0x16,(byte)0x24,(byte)0x64,(byte)0x53,
(byte)0x30,(byte)0xf0,(byte)0xfb,(byte)0xf0,(byte)0x10,(byte)0x3c,(byte)0x54,(byte)0x7d,(byte)0xa5,(
byte)0x47,(byte)0xc1,(byte)0xf0,(byte)0x3b,(byte)0x1c,(byte)0x2b,(byte)0xb5,
(byte)0xcd,(byte)0xd0,(byte)0x6d,(byte)0x38,(byte)0xd2,(byte)0xab,(byte)0xfa,(byte)0xfd,(byte)0x06,(
byte)0x38,(byte)0x72,(byte)0x35,(byte)0xe8,(byte)0xe4,(byte)0x9d,(byte)0xed,
(byte)0xcb,(byte)0x7e,(byte)0x2b,(byte)0x7e,(byte)0x80,(byte)0xa1,(byte)0x5b,(byte)0x13,(byte)0x17,(
byte)0xa0,(byte)0x4e,(byte)0xcf,(byte)0x1a,(byte)0xdb,(byte)0xf4,(byte)0x75,
(byte)0xac,(byte)0x82,(byte)0xd6,(byte)0x75,(byte)0x14,(byte)0xa6,(byte)0xef,(byte)0x5e,(byte)0xbf,(
byte)0xfa,(byte)0xd4,(byte)0x0d,(byte)0x5d,(byte)0x5f,(byte)0x73,(byte)0x95,
(byte)0x17,(byte)0x96,(byte)0x77,(byte)0x70,(byte)0x3b,(byte)0xfc,(byte)0x3a,(byte)0x9d,(byte)0x34,(
byte)0x62,(byte)0x3b,(byte)0xd2,(byte)0x8e,(byte)0xc9,(byte)0x18,(byte)0x6a,
(byte)0x10,(byte)0x78,(byte)0x13,(byte)0x06,(byte)0x52,(byte)0x55,(byte)0x2d,(byte)0x5c,(byte)0xfe,(
byte)0xf1,(byte)0xb6,(byte)0xcd,(byte)0xba,(byte)0x51,(byte)0x97,(byte)0x91,
(byte)0x0a,(byte)0x4c,(byte)0x87,(byte)0xca,(byte)0xd1,(byte)0xf9,(byte)0x2f,(byte)0xa7,(byte)0xeb,(
byte)0x7a,(byte)0x0b,
// END of TEST TLS

							 (byte)0, // Alias-Type
							 (byte)3, // Alias Length
							 (byte)'b',(byte)'b',(byte)'b', // Alias Value						   
							 (byte)8, // EAP-ID Length
							 (byte)'a',(byte)'u',(byte)'r',(byte)'e',(byte)'l', // EAP-ID Value
							 (byte)'i',(byte)'e',(byte)'n', 
		                     EAP_TYPE_PSK, // EAP-Type
							 (byte)3, // Number of Keys
							  KEY_TYPE_SYMETRIC, // Key type
							 (byte)0,(byte)16, // Key Length
							 (byte)0x2B ,(byte)0x7E ,(byte)0x15 ,(byte)0x16 ,
							 (byte)0x28 ,(byte)0xAE ,(byte)0xD2 ,(byte)0xA6, 
	                         (byte)0xAB ,(byte)0xF7 ,(byte)0x15 ,(byte)0x88 ,
							 (byte)0x09 ,(byte)0xCF ,(byte)0x4F ,(byte)0x3C,
							 
							  KEY_TYPE_PMK, // Key type
							 (byte)0,(byte)64, // Key Length
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
                             (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
                             (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							 (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,
							 (byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,
							  KEY_TYPE_ID, // Key type
							 (byte)0,(byte)19, // Key Length
							 (byte) 8,
							 (byte)'a',(byte)'u',(byte)'r',(byte)'e',(byte)'l',
							 (byte)'i',(byte)'e',(byte)'n', 
							 (byte) 9,
							 (byte)'p',(byte)'s',(byte)'k',(byte)'s',(byte)'e',
							 (byte)'r',(byte)'v',(byte)'e',(byte)'r', 
	                         
	  (byte)-1,// End of Records
	  (byte)0,(byte)0// status
	};  
	
	
  private final static  byte RAZ= (byte)0 ;
  private final static  byte GET= (byte)1 ;
  private final static  byte SET= (byte)2 ;
  private final static  byte GETNEXT = (byte)3 ;
  
  private final static  byte  CLASS_EAP             = (byte) 0xA0;
	
  private final static  byte  INS_GET_CURRENT_IDENTITY=(byte)0x18;
  private final static  byte  INS_GET_NEXT_IDENTITY = (byte) 0x17;
  private final static  byte  INS_SET_IDENTITY      = (byte) 0x16;
  private final static  byte  INS_EAP_PACKETS       = (byte) 0x80;
  private final static  byte  INS_GET_RSN_MASTER_KEY= (byte) 0xA6;
  private final static  byte  INS_VERIFY            = (byte) 0x20;
  private final static  byte  INS_CHANGE_PIN        = (byte) 0x24;
  private final static  byte  INS_FCT               = (byte) 0x60;
  private final static  byte  INS_FETCH             = (byte) 0x12;  
  private final static  byte  INS_SELECT            = (byte) 0xA4 ;
  private final static  byte  INS_READ              = (byte) 0xB0 ;
  private final static  byte  INS_WRITE             = (byte) 0xD0 ;
  
  private final static  byte  P2_GET_NEXT_IDENTITY=(byte)0x01 ;
  private final static  byte  P2_SET_IDENTITY     =(byte)0x80 ;
	
    
  private final static  byte EAP_CODE   = (byte)0 ;
  private final static  byte EAP_IDT    = (byte)1 ;
  private final static  byte EAP_LENGTH = (byte)2 ;
  private final static  byte EAP_TYPE   = (byte)4 ;
  private final static  byte EAP_DATA   = (byte)5 ;
  
   
  private final static  byte EAP_Code_Request     = (byte) 1 ;
  private final static  byte EAP_Code_Response    = (byte) 2 ;
  private final static  byte EAP_Code_Success     = (byte) 3 ;
  private final static  byte EAP_Code_Failure     = (byte) 4 ;
    
  private  static byte  MyEAPType = (byte)0     ;
  
  public  static boolean IdentitySet=false ;
 
  private  static short MyKey_Length = (short)0 ;
  private  static short MyKey_Offset = (short)0 ;
  
  private  static short MyCert_Length = (short)0 ;
  private  static short MyCert_Offset = (short)0 ;
   
  private  static byte  My_Identity_Identity_Type = (byte)0;
  
  private  static short My_Identity_Length=(short)0  ;
  private  static short My_Identity_Offset= (short)0 ;
  
  private  static short My_ID_Length=(short)0  ;
  private  static short My_ID_Offset= (short)0 ;
  
   
  // Up to 256 bits
  private static byte   My_PMK_Key_Default[] = 
                                           {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
   									        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
											(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00}; 
  
  private  static byte []My_PMK_Key        = null     ;
  private  static short  My_PMK_Key_Offset = (short)0 ;
  private  static short  My_PMK_Key_Length = (short)64;			
 			
  private  static short My_Alias_Length=(short)0 ;
  private  static short My_Alias_Offset=(short)0 ;
    
  private  static short Index= (short)0;
  private  static short LastIndex= (short)0;
  
  private  static MessageDigest md5=null ;
  private  static MessageDigest sha=null ;
  
  private  static RSAPrivateCrtKey    rsa_PrivateCrtKey=null;
  private  static RSAPublicKey        rsa_PublicKey=null;
  private  static RSAPublicKey        rsa_PublicKeyCA=null;
  private  static RSAPublicKey        rsa_PublicKeyCA_1024=null;
  private  static RSAPublicKey        rsa_PublicKeyCA_2048=null;
  private  static Cipher              cipherRSA=null;
  private  static RandomData          rnd=null ;
  
  private static OwnerPIN UserPin=null;
  private static final  byte[]   MyPin = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,
                                          (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
    
  private static OwnerPIN OperatorPin=null;
  private static final  byte[]   OpPin = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30,
						                  (byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30};
  
  private final static short  SW_VERIFICATION_FAILED        = (short)0x6300;
  private final static  short SW_PIN_VERIFICATION_REQUIRED  = (short)0x6301;
  private final static short  SW_FETCH                      = (short)0x9F00;
  
  private  static short Out_ptr=(short)0,Out_len=(short)0;
  private  static byte[] Out_ref=null;
   
  private static auth EAPAuth=null ;
  
  private static credentialtls TlsCredit= null; 
  private static methodtls     TlsMethod= null; 
   
  private static credentialpsk PskCredit= null;
  private static methodpsk     PskMethod= null;
 
  /**
   * EAP Engine Initialization. 
   * Called during the Install process
   */ 
  public void Initialize() 
  {short i=0,stat=0;
    
   NVR    = new byte[NVR_Size];
   Util.arrayCopy(NVR_Test,(short)0,NVR,(short)0,(short)NVR_Test.length);
   // NVR_Size = (short)NVR.length   ;
   
   TlsCredit=   new credentialtls() ;
   TlsMethod  = new methodtls()     ;
     
   PskCredit= new credentialpsk() ;
   PskMethod= new methodpsk();
      
  
   
   My_PMK_Key = My_PMK_Key_Default ;
   
   // Attempt to get an MD5 interface
   try 	  { md5=MessageDigest.getInstance(MessageDigest.ALG_MD5,false);}
   catch (CryptoException e){md5=null;}
      
   // Attempt to get an SHA-1 interface
   try 	  { sha=MessageDigest.getInstance(MessageDigest.ALG_SHA,false); }
   catch (CryptoException e){sha=null;}	
 
      
   UserPin     = new OwnerPIN((byte)3,(byte)8) ;  // 3  tries 4=Max Size
   OperatorPin = new OwnerPIN((byte)10,(byte)8);  // 10 tries 8=Max Size
      
   UserPin.update(MyPin,(short)0,(byte)8);
   OperatorPin.update(OpPin,(short)0,(byte)8);
   
   //====================================================
      try 	  {   // Client Public Key
	  rsa_PublicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_1024,false); }
	  catch (CryptoException e){}
	  
	  try 	  {   // CA_Public_Key
	  rsa_PublicKeyCA_2048 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_2048,false); }
	  catch (CryptoException e){}
	  
	  try 	  {   // CA_Public_Key
	  rsa_PublicKeyCA_1024 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_1024,false); }
	  catch (CryptoException e){}
	  	  
	  try {
	  rsa_PrivateCrtKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE,KeyBuilder.LENGTH_RSA_1024,false); }
	  catch (CryptoException e){}
	  try {
	  cipherRSA     = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false); }
	  catch (CryptoException e){}
	  
	  try {
	  rnd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);}
	  catch (CryptoException e){}
	  
	  stat = Util.getShort(NVR,(short)(NVR_Size-2));
	 	  
	  if (md5 != null)                 stat =  (short) ( stat  | 1);
	  if (sha != null)                 stat =  (short) ( stat  | 2);
	  if (rsa_PublicKey != null)       stat =  (short) ( stat  | 4);    
	  if (rsa_PrivateCrtKey != null)   stat =  (short) ( stat  | 8);
	  if (cipherRSA != null)           stat =  (short) ( stat  | 16);    
	  if (rnd != null)                 stat =  (short) ( stat  | 32); 
	  if (rsa_PublicKeyCA_1024 !=null) stat =  (short) ( stat  | 64); 
	  if (rsa_PublicKeyCA_2048 !=null) stat =  (short) ( stat  | 128); 
	  
	    
	  Util.setShort(NVR,(short)(NVR_Size-2),stat);

}
  
  /** 
   * Verifies the user's or the issuer's PIN code
   * <br>pin:    an OwnerPIN object
   * <br>buffer: the incoming APDU 
   */
  public void verify(OwnerPIN pin,byte [] buffer) throws ISOException
  {short i,x;
   
   x = Util.makeShort((byte)0,buffer[4]);
   
   for(i=x;i<(short)8;i=(short)(i+1))
	   buffer[(short)(5+i)]=(byte)0xFF;
	  
   if ( pin.check(buffer, (short)5,(byte)8) == false )
   ISOException.throwIt((short)((short)SW_VERIFICATION_FAILED | (short)pin.getTriesRemaining()));
  }
  
  
  /**
   * Identity Management
   * <br>mode: RAZ - SET - GET - GETNEXT
   * <br>Identity value: buffer, offset, length
   * <br>Returns: the identity length, or 0 if an error occured
   */
  public short identity(byte mode,byte[] buffer,short offset,short length)
  { short nk,i,len=(short)0;
	byte  TmpAlias_Identity_Type;
	short TmpAlias_Length,TmpAlias_Offset,TmpIdentity_Ref ;
	
	if (mode == RAZ) {Index = (short)0 ; IdentitySet=false ; return(0);}
	
	if (mode == SET)  Index = (short)0 ;
	
	if ((NVR[Index] == (byte)-1) && (Index == (short)0))  return(0); // Empty Memory
	
	for(;;)
	{
	if (NVR[Index] == (byte)-1) 
	{ Index= (short) 0 ; // Wrap Around
	  return(0);         // Record not found
	}   
		
	TmpAlias_Identity_Type = NVR[Index]  ; 
	TmpAlias_Length        = Util.makeShort((byte)0,NVR[(short)(Index+1)])   ; 
	TmpAlias_Offset        = (short)(Index+2)                                ; 
	TmpIdentity_Ref        = (short)(TmpAlias_Length+Index+2)                ;
		
	if (mode != GET)  // compute index for EAP-Type value
	{ Index = (short)(Index+2+TmpAlias_Length)                      ; // => Identity_Length
	  Index = (short)(Index+1+Util.makeShort((byte)0,NVR[Index]))   ; // => EAP-Type
	}  
	                
	if ( (mode == GET) || (mode == GETNEXT) )
	{	
	  if (mode == GETNEXT)                     // compute new index
	  {  nk = (short) NVR[(short)(1+Index)] ;  // Number of Keys
	     Index = (short)(Index+2)           ;  // => Key_Index , Key_Length
	     for(i=0;i<nk;i=(short)(i+1))
	     Index = (short)(Index+3+Util.makeShort(NVR[(short)(Index+1)],NVR[(short)(Index+2)])); // => Next_Key_Index
	  }
	  Util.arrayCopyNonAtomic(NVR,TmpAlias_Offset,buffer,offset,TmpAlias_Length); 
	  
	  if (NVR[Index] == (byte)-1) Index= (short) 0 ;
	  return(TmpAlias_Length);
	}
		
	
	Index = (short)(Index+1);  // => Number of Keys
	nk = (short) NVR[Index] ;  // => Number of Keys
	Index = (short)(Index+1);  // => Key_Type
		
	if ( TmpAlias_Length != length) // GoTo NextRecord
	{ for(i=0;i<nk;i=(short)(i+1))
	  Index = (short)(Index + 3 + Util.makeShort(NVR[(short)(Index+1)],NVR[(short)(Index+2)])) ;
	}
	
	else if (Util.arrayCompare(buffer,offset,NVR,TmpAlias_Offset,TmpAlias_Length)!=0)
	{ for(i=0;i<nk;i=(short)(i+1)) // Goto NextRecord
	  Index = (short)(Index + 3 + Util.makeShort(NVR[(short)(Index+1)],NVR[(short)(Index+2)])) ;
	}

	
	else 
	{ 
	  EAPAuth = null;
	  MyEAPType = NVR[(short)(Index-2)] ;
	  
	  for(i=0;i<nk;i=(short)(i+1))
	  { //MyKey_Type = NVR[Index] ;
		len = Util.makeShort(NVR[(short)(Index+1)],NVR[(short)(Index+2)]) ;
		//Index = (short)(Index+3) ;
		
		switch (NVR[Index])
	   {
		case KEY_TYPE_SYMETRIC:
		// MyKey_Index  = (byte)i    ;
		MyKey_Length = len                 ;
	    MyKey_Offset = (short)(Index+3)    ;
		
		My_PMK_Key_Length= (short)64 ;
		My_PMK_Key_Offset=  (short) 0;
		My_PMK_Key       = My_PMK_Key_Default ;
				
		Index = (short)(3+Index+len);
	   	break;
		
		case KEY_TYPE_PMK:
		My_PMK_Key         = NVR;
		My_PMK_Key_Length  =  (short)64 ;
	    My_PMK_Key_Offset  =  (short)(Index+3) ;
		  
		Index = (short)(3+Index+len);
	    break;	
		 
		case KEY_TYPE_RSA_PRIVATE_CRT:
		
		Index = (short)(3+Index); 
		
		len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		
		// Create Cipher 
		if (rsa_PrivateCrtKey != null)
		{try{rsa_PrivateCrtKey.setQ(NVR, (short)(Index+2), len);}
		 catch (CryptoException e){}
		}
		
		Index = (short)(Index+2+len);
		len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		
		if (rsa_PrivateCrtKey != null)
		{try{rsa_PrivateCrtKey.setP(NVR, (short)(Index+2), len);}
		 catch (CryptoException e){}
		}
		
		Index = (short)(Index+2+len);
		len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		
		if (rsa_PrivateCrtKey != null)
		{try{rsa_PrivateCrtKey.setPQ(NVR, (short)(Index+2), len);}
		 catch (CryptoException e){}
		}
		
		Index = (short)(Index+2+len);
		len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		
		if (rsa_PrivateCrtKey != null)
		{ try{rsa_PrivateCrtKey.setDQ1(NVR, (short)(Index+2), len);}
		  catch (CryptoException e){}
		}
		
		Index = (short)(Index+2+len);
		len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		
		if (rsa_PrivateCrtKey != null)
		{try{rsa_PrivateCrtKey.setDP1(NVR, (short)(Index+2), len);}
		 catch (CryptoException e){}
		}
		
		Index = (short)(Index+2+len);len=(short)0;
		 
		 break;

		case KEY_TYPE_RSA_PUBLIC:
		 Index = (short)(3+Index);
		 len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		 
		 if (rsa_PublicKey != null)
		 { try{rsa_PublicKey.setModulus(NVR, (short)(Index+2), len);}
		   catch (CryptoException e){}
		 }
		 
		 Index = (short)(Index+2+len);
		 len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		
		if (rsa_PublicKey != null)
		{ try{rsa_PublicKey.setExponent(NVR, (short)(Index+2), len);}
		  catch (CryptoException e){}
		}
		
		Index = (short)(Index+2+len);len=(short)0;
		break;
		 
		 case KEY_TYPE_RSA_PUBLIC_CA:
		 Index = (short)(3+Index);
		 len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		 		 
		 if (len == (short)128)       rsa_PublicKeyCA = rsa_PublicKeyCA_1024  ;
		 else if (len == (short)256)  rsa_PublicKeyCA = rsa_PublicKeyCA_2048  ;
		 else                 		  rsa_PublicKeyCA = null;  
		 
		 if (rsa_PublicKeyCA != null)
		 { try{rsa_PublicKeyCA.setModulus(NVR, (short)(Index+2), len);}
		   catch (CryptoException e){}
		 }  
		 Index = (short)(Index+2+len);
		 len = Util.makeShort(NVR[Index],NVR[(short)(Index+1)]);
		 
		 if(rsa_PublicKeyCA != null)
		 {try{rsa_PublicKeyCA.setExponent(NVR, (short)(Index+2), len);}
		  catch (CryptoException e){}
		 }
		 Index = (short)(Index+2+len);len=(short)0;
		 break;
		 		 
		 case KEY_TYPE_RSA_CERT:
		 MyCert_Length = len  ;
	     MyCert_Offset = (short)(Index+3);
		 Index = (short)(3+Index+len);
		 
		 break;	
		 
	  }  
	}
	
	  switch (MyEAPType)
		{ case EAP_TYPE_TLS:
		 
		 TlsCredit.Cert_Length = MyCert_Length  ;
	     TlsCredit.Cert_Offset = MyCert_Offset  ;
		 TlsCredit.Cert        = NVR;
		  
		 TlsCredit.PMK_Key        = My_PMK_Key        ;
		 TlsCredit.PMK_Key_Length = My_PMK_Key_Length ;
	     TlsCredit.PMK_Key_Offset = My_PMK_Key_Offset ;
		  
		 TlsCredit.sha = sha ;
	     TlsCredit.md5 = md5 ;
	     TlsCredit.rsa_PublicKey     = rsa_PublicKey ;
	     TlsCredit.rsa_PrivateCrtKey = rsa_PrivateCrtKey;
	     TlsCredit.cipherRSA         = cipherRSA;
		 TlsCredit.rsa_PublicKeyCA   = rsa_PublicKeyCA;
	     TlsCredit.rnd               = rnd;
		  
		 TlsCredit.enable_resume= TlsCredit.test = TlsCredit.step = false;
		 
		 if ( (short)(Util.getShort(NVR,(short)(NVR_Size-2)) & (short)0x8000) == (short)0x8000)
         TlsCredit.test=true;
		 
		 if ( (short)(Util.getShort(NVR,(short)(NVR_Size-2)) & (short)0x4000) == (short)0x4000)
         TlsCredit.step=true;
         
		 if ( (short)(Util.getShort(NVR,(short)(NVR_Size-2)) & (short)0x2000) == (short)0x2000)
		 TlsCredit.enable_resume=true;
		 
	      ////////////////////////////////////////////
		  EAPAuth = TlsMethod.Init((Object)TlsCredit);
		  ////////////////////////////////////////////
		 
		 break;
		
		  case EAP_TYPE_PSK:
		  
		  PskCredit.PMK_Key        = My_PMK_Key        ;
		  PskCredit.PMK_Key_Length = My_PMK_Key_Length ;
	      PskCredit.PMK_Key_Offset = My_PMK_Key_Offset ; 
		 
		  PskCredit.ID_P_Length = Util.makeShort((byte)0,NVR[MyCert_Offset])  ;
	      PskCredit.ID_P_Offset = (short)(MyCert_Offset+1)  ;
		  PskCredit.ID_P        = NVR;
		  
		  PskCredit.ID_S_Length = Util.makeShort((byte)0,NVR[(short)(PskCredit.ID_P_Offset+PskCredit.ID_P_Length)])  ;
	      PskCredit.ID_S_Offset = (short)(1+PskCredit.ID_P_Offset+PskCredit.ID_P_Length)  ;
		  PskCredit.ID_S        = NVR;
		  
		  PskCredit.PSK_Key_Length = MyKey_Length  ;
	      PskCredit.PSK_Key_Offset = MyKey_Offset  ;
		  PskCredit.PSK_Key        = NVR;
		  
		  PskCredit.rnd = rnd;
		  
		  if ( (short)(Util.getShort(NVR,(short)(NVR_Size-2)) & (short)0x8000) == (short)0x8000)
          PskCredit.test=true;
		  else PskCredit.test= false;
		  
		  if ( (short)(Util.getShort(NVR,(short)(NVR_Size-2)) & (short)0x4000) == (short)0x4000)
          PskCredit.step=true;
		  else PskCredit.step= false;
		  
		  ////////////////////////////////////////////
		  EAPAuth = PskMethod.Init((Object)PskCredit);
		  ////////////////////////////////////////////
		  break;
			
	    }
	       
	  My_Identity_Identity_Type = TmpAlias_Identity_Type;
	  My_Identity_Length        = Util.makeShort((byte)0,NVR[TmpIdentity_Ref]) ;
	  My_Identity_Offset        = (short) (TmpIdentity_Ref+1) ;
	  
	  My_ID_Length = TmpAlias_Length ;
	  My_ID_Offset = TmpAlias_Offset ;
	  IdentitySet=true ;
	  
	  if (NVR[Index] == (byte)-1) Index= (short) 0 ;
	  
	  return(My_Identity_Length);
	}
	
	} // Other record
	
	}
  
  /**
   * Returns the current EAP type
   */
  public byte Get_EAP_Type() 
	{ return MyEAPType; } 

  /**
   * EAP messages processing
   * <br>buffer:  buffer previoulsy linked to the incoming APDU
   * <br>length:  APDU body length, e.g. P3 value
   * <br>apdu:    incoming APDU  
   * <br>Returns: 
   * <br>- a positive value (response or fragment length)if no errors occurs
   * <br>- a zero value is a delay is needed (debug mode)
   * <br>- a negative value if an error occured
   */
  public short Process_EAP (byte[] buffer,short length,APDU apdu) throws ISOException
	{ short Length,inLength=(short)0,i;
	  byte type,code ;
	
	  	 
	 if ((EAPAuth != null)&& EAPAuth.IsFragmented() ) 
	 {  type = MyEAPType ;code = EAP_Code_Request; }
	 
	 else
	 { type = buffer[(short)(5+EAP_TYPE)];  // EAP-Type
	   code = buffer[(short)(5+EAP_CODE)];  // EAP-code
	   inLength = Util.makeShort(buffer[(short)(5+EAP_LENGTH)],buffer[(short)(6+EAP_LENGTH)]); // EAP-Length
	 }
		  
	 
	  switch (code) // EAP-Code
	  { 
	  case EAP_Code_Request:  // request
		  
		  switch (type) // EAP-Type
		  { 
		  case EAP_TYPE_IDENTITY:
			  
			  buffer[EAP_CODE]= EAP_Code_Response ;         // Response ;
			  buffer[EAP_IDT] = buffer[(short)(EAP_IDT+5)];
			  Util.setShort(buffer,(short)EAP_LENGTH,(short)(My_Identity_Length+5));
			  buffer[EAP_TYPE]= EAP_TYPE_IDENTITY ;
			  
			  Util.arrayCopyNonAtomic(NVR,My_Identity_Offset,buffer,(short)EAP_DATA,My_Identity_Length); 
			  
			   if (EAPAuth != null)
			   EAPAuth.reset();
			  
			  return((short)(My_Identity_Length+5));
					  
		  case EAP_TYPE_MD5:
			  
			  if (type != MyEAPType) return((short)5) ;
			  
			  if (md5 == null)    return((short)5) ;
			 			  
			  buffer[EAP_CODE]= EAP_Code_Response ; // response ;
			  buffer[EAP_IDT] = buffer[(short)(EAP_IDT+5)];
			  buffer[EAP_TYPE]= type;
			 			  
			  md5.reset();
						  
			  Util.arrayCopyNonAtomic(buffer,
			 						 (short)(1+5+EAP_DATA),
			  					      buffer,
									 (short)(1+5+EAP_DATA+MyKey_Length),
									 (short)(inLength-EAP_DATA-1)); 
		
			  Util.arrayCopyNonAtomic(NVR,
			  				     MyKey_Offset,
								 buffer,
								 (short)(1+5+EAP_DATA),
								 MyKey_Length); 
			 
			  buffer[(short)(5+EAP_DATA)] = buffer[(short)(EAP_IDT+5)];
			  
			  Length= md5.doFinal(buffer,(short)(5+EAP_DATA),(short)(inLength-EAP_DATA+MyKey_Length),
						          buffer,(short)(EAP_DATA+1));
			  
			  Util.setShort(buffer,(short)EAP_LENGTH,(short)(Length+5+1) );	
			  
			  buffer[EAP_DATA]= (byte) Length;	
			  
			  return((short)(1+5+Length));
			  
		  case EAP_TYPE_SHA1:
			  
			  if (type != MyEAPType) return((short)5) ;
			  
			  if (sha==null) return((short)5) ;
			  			 												
              buffer[EAP_CODE]= EAP_Code_Response ; // response ;
			  buffer[EAP_IDT] = buffer[(short)(EAP_IDT+5)];
			  buffer[EAP_TYPE]= type;
			 			  
			  sha.reset();
			  
			  Util.arrayCopyNonAtomic(buffer,
			 						 (short)(1+5+EAP_DATA),
			  					      buffer,
									 (short)(1+5+EAP_DATA+MyKey_Length),
									 (short)(inLength-EAP_DATA-1)); 
		
			  Util.arrayCopyNonAtomic(NVR,
			  				     MyKey_Offset,
								 buffer,
								 (short)(1+5+EAP_DATA),
								 MyKey_Length); 
			 
			  buffer[(short)(5+EAP_DATA)] = buffer[(short)(EAP_IDT+5)];
			  
			  Length= sha.doFinal(buffer,(short)(5+EAP_DATA),(short)(inLength-EAP_DATA+MyKey_Length),
						          buffer,(short)(EAP_DATA+1));
			  
			  
			  //========================================
			  if (My_PMK_Key_Offset !=  (short)0 )
			  { 
				  Util.arrayCopyNonAtomic(buffer,
			  				     (short)(EAP_DATA+1),
								 buffer,
								 (short)(EAP_DATA+1+20),
								 (short)20); 
				  
			  for(i=(short)0;i<(short)4;i=(short)(i+1))
			  {
			  sha.reset();
			  	  
			  Util.arrayCopyNonAtomic(NVR,
			  				     MyKey_Offset,
								 buffer,
								 (short)(1+EAP_DATA+40),
								 MyKey_Length); 
			  
			  
			  Length= sha.doFinal(buffer,
								  (short)(EAP_DATA+1+20),
								  (short)(20+MyKey_Length),
						          buffer,
								  (short)(EAP_DATA+1+20));
			  
			  if (i != (short)3)
			  Util.arrayCopyNonAtomic(buffer,(short)(1+EAP_DATA+20),My_PMK_Key,(short)(My_PMK_Key_Offset+20*i),(short)20);
			  else
              Util.arrayCopyNonAtomic(buffer,(short)(1+EAP_DATA+20),My_PMK_Key,(short)(My_PMK_Key_Offset+20*i),(short)4);
			 
			  }
			  }
			  
			  //=======================================================================================
			  
			  //Length=20;
			  
			  Util.setShort(buffer,(short)EAP_LENGTH,(short)(Length+5+1) );															;
			  
			  buffer[EAP_DATA]= (byte) Length;	
			  
			  return((short)(1+5+Length));
			  
			  		
		case EAP_TYPE_PASSWORD: // Password
		  
		  if (type != MyEAPType) return((short)5) ;
		  
		  buffer[EAP_CODE]= EAP_Code_Response; // Response
		  buffer[EAP_IDT] = buffer[(short)(EAP_IDT+5)];
		  Util.setShort(buffer,(short)EAP_LENGTH,(short)(MyKey_Length+5+1));
		  buffer[EAP_TYPE]= MyEAPType ;
		  
		  buffer[EAP_DATA]= (byte) MyKey_Length ;
		
		  Util.arrayCopyNonAtomic(NVR,MyKey_Offset,buffer,(short)(EAP_DATA+1),MyKey_Length); 
			  
		  return((short)(MyKey_Length+1+5));
		  
		default: // TLS ... NAK 
		  if (EAPAuth != null)
		  { try { length = EAPAuth.process_eap(buffer,(short)(length+5));}
		    catch (CryptoException e){length=(short)-1;}
			
			if (EAPAuth.IsLongResponse())
			{ Out_ref = EAPAuth.Get_Out_Buffer();
			  Out_ptr = EAPAuth.Get_Out_Offset();
			  Out_len = length;
			  LongResponse(true,buffer,apdu);
			  return(short)0;
			}
			
		    return(length);
		  }
			  
		  else
		  { buffer[EAP_CODE]= EAP_Code_Response             ;      // Default Response ;
	        buffer[EAP_IDT] = buffer[(short)(EAP_IDT+5)]    ;
	        Util.setShort(buffer,(short)EAP_LENGTH,(short)5);      // Length = 05 bytes
	        buffer[EAP_TYPE]= EAP_TYPE_NAK                  ;      // NAK
		    return((short)5) ;
		  }
			  
	   } // End of Request
		  
      		  
	  case EAP_Code_Response:  //Response:
		  break;
		  
	  case EAP_Code_Success:   // Success:
	      break;
		  
	  case EAP_Code_Failure:  // Failure:
		  break; 
		  
	  default:  // Other EAP Code
		  break;	  
	  }
	  
	return(0);
	
	}
	
	
/**
 * Returns the PMK Key
 * <br>buffer: the buffer linked to the incomoing APDU
 * <br>length: length of the key (e.g. P3 value)
 * <br>Returns
 * <br>-length of the key value
 * <br>-0, if a an eror occured 
 */	
public short Get_MasterKey(byte []buffer, short length)
	{   if (length < 0) return(short)0;
		else if (length == 0)
		{ Util.arrayCopyNonAtomic(My_PMK_Key,My_PMK_Key_Offset,buffer,(short)0,My_PMK_Key_Length); 
		  return (My_PMK_Key_Length);
		}
		else if (length > My_PMK_Key_Length) return (short)0;
		
		Util.arrayCopyNonAtomic(My_PMK_Key,My_PMK_Key_Offset,buffer,(short)0,length); 
		return (length);	
			
	}

/**
 * Resets the current EAP method.
 */

public void reset() 
{   if (EAPAuth != null) EAPAuth.reset();
	return;
}

/** 
 * Returns the status of the current EAP method.
 */
public short status() 
{   if (EAPAuth != null) return EAPAuth.status();
	return(0);	}
  

public void process(APDU apdu) throws ISOException
  {	
  byte[] buffer = apdu.getBuffer() ; // CLA INS P1 P2 P3
  
  byte cla = buffer[ISO7816.OFFSET_CLA];
  byte ins = buffer[ISO7816.OFFSET_INS];
  byte P1  = buffer[ISO7816.OFFSET_P1] ;
  byte P2  = buffer[ISO7816.OFFSET_P2] ;
  byte P3  = buffer[ISO7816.OFFSET_LC] ; 
  
  short adrc = Util.makeShort(buffer[2],buffer[3])  ;
  short len  = Util.makeShort((byte)0,buffer[4])    ;
  
  switch (ins)
		{
        case INS_FCT:
	    
	    if ( ! UserPin.isValidated() && !OperatorPin.isValidated() )
		ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)UserPin.getTriesRemaining()));
			  
	    if ( ((short)(Util.getShort(NVR,(short)(NVR_Size-2)) & (short)0x1000) == (short)0x1000))
		ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);	
	   	
		if (EAPAuth != null) 
		{ try {EAPAuth.fct(apdu,buffer,len);}
		   catch (CryptoException e)
		   {ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);}
		}
		
		if (EAPAuth.IsLongFct())
		{ Out_ref = EAPAuth.Get_Fct_Buffer() ;
		  Out_ptr = EAPAuth.Get_Fct_Offset();
		  Out_len = EAPAuth.Get_Fct_Length();
		  LongResponse(false,buffer,apdu) ;
		}
		break;	 
		
		case INS_SELECT: 
	    len = apdu.setIncomingAndReceive(); 
	  	return;			
		
		case INS_VERIFY:   // retrieve the PIN data for validation.
                       apdu.setIncomingAndReceive()        ;
					   if (P2 == (byte)0x01)
					   { verify(OperatorPin,buffer) ;
						 if(OperatorPin.isValidated()) UserPin.resetAndUnblock();
						 
					   }
					   else 
					   {	   verify(UserPin,buffer)     ;
					   }
                       break;			
		
		case INS_CHANGE_PIN:   // retrieve the PIN data for validation.
                       len= apdu.setIncomingAndReceive() ;
					   
					   if (len != (short)16)
						   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
						   
					   buffer[4]=(byte)8;
					   
					   if (P2 == (byte)0x01)
					   {  verify(OperatorPin,buffer) ;
						  OperatorPin.update(buffer,(short)13,(byte)8);
					   }
					   else  
					   { verify(UserPin,buffer)  ;
						 UserPin.update(buffer,(short)13,(byte)8);
					   }
					  				   
					   
                       break;	
					   
        case INS_GET_CURRENT_IDENTITY:	
		
		if ( ! UserPin.isValidated() && !OperatorPin.isValidated() )
		ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)UserPin.getTriesRemaining()));
				
					   
		Util.arrayCopyNonAtomic(NVR,My_ID_Offset,buffer,(short)0,My_ID_Length);
		apdu.setOutgoingAndSend((short)0,My_ID_Length)                        ;			   
		
		break;
					   
		case INS_GET_NEXT_IDENTITY :
		case INS_SET_IDENTITY :	
					   
		if ( ! UserPin.isValidated() && !OperatorPin.isValidated() )
		ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)UserPin.getTriesRemaining()));
				
		
        switch (P2)
		{
        case (P2_GET_NEXT_IDENTITY):
				  	       
			       if ((P3 == (byte)0)&& (APDU.getProtocol() == APDU.PROTOCOL_T0) )				   
		  	       len =identity(GET,buffer,(short)0,(short)-1);
			       else 
				   len =identity(GETNEXT,buffer,(short)0,(short)-1);
				   
				   if(len == (short)0) 
				   ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				   
				   apdu.setOutgoingAndSend((short)0,len)  ; 
				   // 6C XX
 				   break ;
				
		case (P2_SET_IDENTITY):
				  len = apdu.setIncomingAndReceive(); 	
				  
				  if ( ! UserPin.isValidated() && !OperatorPin.isValidated() )
			      ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
								  
				  len =identity(SET,buffer,(short)5,len);
				  
				  if (len ==0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				  // 90 00
				  
				  break;
				  
	    default:  // Bad P1 value
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);		
		} 
		break;
		
		case INS_EAP_PACKETS :
		         
		        if ( ! UserPin.isValidated() && !OperatorPin.isValidated() )
			    ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)UserPin.getTriesRemaining()));
     			
				len = apdu.setIncomingAndReceive(); 
				
				len = Process_EAP(buffer,(short)len,apdu);
							  
				if (len <0) 
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				 
				else if (len >0) 
					apdu.setOutgoingAndSend((short)0,len)  ;
				// 61 XX
				break;
					
		case INS_GET_RSN_MASTER_KEY :
				
				if ( ! UserPin.isValidated() && !OperatorPin.isValidated() )
			    ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)UserPin.getTriesRemaining()));
		
				
				if (P3 == (byte)0)				   
		  	    len = Get_MasterKey(buffer,(short)P3) ;
			      
				else 
				len = Get_MasterKey(buffer,(short)P3) ;				  
				  
				if (len ==0) ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				  
				apdu.setOutgoingAndSend((short)0,len) ;
				// 6C XX 
				
				break;	
				   
		case INS_READ:	
				  
				  if ( !OperatorPin.isValidated() )
			      ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)OperatorPin.getTriesRemaining()));
		
				  if (adrc <(short)0) 
					  adrc =(short) (NVR_Size+adrc);
								
				  if (len == (short)0) len = (short)256; 
				  if ((adrc <0) || (adrc >= NVR_Size))      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH) ;
				  else if ((short)(adrc  + len) > NVR_Size) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH) ;
			      Util.arrayCopyNonAtomic(NVR,adrc,buffer,(short)0,len);
				  apdu.setOutgoingAndSend((short)0,len)            ;	
				  break;
				  
        case INS_WRITE:
				  len = apdu.setIncomingAndReceive(); 
				  
				  if ( !OperatorPin.isValidated() )
			      ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)OperatorPin.getTriesRemaining()));
					
				  if (adrc <(short)0) 
					  adrc =(short) (NVR_Size+adrc);
				  
				  if      ((adrc <0) || (adrc >= (short)NVR_Size)) 
				  ISOException.throwIt(ISO7816.SW_WRONG_LENGTH) ;
				  else if ((short)(adrc  + len) > (short)NVR_Size) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH) ;
				  Util.arrayCopyNonAtomic(buffer,(short)5,NVR,adrc,len);
				  
				  identity(RAZ,null,(short)0,(short)0);
				  break;
				  
       case INS_FETCH:
				  
				if ( ! UserPin.isValidated() && !OperatorPin.isValidated() )
			    ISOException.throwIt((short)((short)SW_PIN_VERIFICATION_REQUIRED | (short)UserPin.getTriesRemaining()));
		  				  
				LongResponse(false,buffer,apdu);
				return;
					 
				  
	    default:  
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);	
				return;
  
  }
  
  
  }
/**
 * Output segmentation
 * <br>first: first segment
 * <br>buffer: buffer linked to the incoming APDU
 * <br>apdu: incoming APDU
 */
public  void LongResponse(boolean first,byte []buffer,APDU apdu) throws ISOException
{ short len=(short)256 ;

  if (first & (Out_len > 256) )
	  ISOException.throwIt((short)SW_FETCH) ;
  
  if (len > Out_len) len=Out_len ;
  
  Util.arrayCopyNonAtomic(Out_ref,Out_ptr,buffer,(short)0,len);
  apdu.setOutgoingAndSend((short)0,len) ;
  
  Out_ptr = (short)(Out_ptr+len);
  Out_len = (short)(Out_len-len);
      
  if (Out_len <= 0) return ;
  
  if (Out_len < (short)256) len=Out_len ;
  else                      len=(short)0;
									   
  ISOException.throwIt((short)((short)SW_FETCH | (short)((short)0xFF & len))) ;
  					 
}
   
  protected eapengine(byte[] bArray,short bOffset,byte bLength)
   { Initialize() ;
	 register()   ;
   }

  
  public static void install( byte[] bArray, short bOffset, byte bLength )
  {   
  new eapengine(bArray,bOffset,bLength);		
  }

  public boolean select()
  { UserPin.reset()    ;
	OperatorPin.reset();
	reset();
    return true;
  }

  public void deselect()
  { 
  }
 
  public eapengine()
  {  return;
  }
   
}
  





