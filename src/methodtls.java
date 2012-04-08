/* methodtls.java */
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
 
 
/****************************************************************************************************************
 | UPDATE 2011 - Gilles Bernabé                                                                                 |
 |--------------------------------------------------------------------------------------------------------- ----|
 | - remove cypher suite TLS_RSA_WITH_RC4_128_SHA and implementation of TLS_RSA_WITH_AES_128_CBC_SHA            |
 | - implementation of the entire TLS Record protocol								|           
 | - possibility to transmit the password from smart card to server through TLS for authentication on a service |
 | - update RSA 1024 to RSA 2048 for client signature and encryption with server public key                     |
 | - minor changes: memory management, harden certificate checking, cleanups...                                 |
 ****************************************************************************************************************/
 
 
package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class methodtls implements auth {

//===============================================================
	/**
	* Set this value to 10000 if smartcard doesn't support digest update method
	*/
	public final static short digest_limit = (short)128;
	/**
	* Maximum size of an EAPTLS body (length value excluded)
	*/
	public  final static short EAP_FRAGMENT_SIZE = (short)1484;
	/**
	* Enable the TLS secure channel mode
	*/
	public  static boolean enable_channel= true;
	//CipherSuite TLS_RSA_WITH_RC4_128_SHA = { 0x00,0x05 };
	//CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA = { 0x00,0x2F };
	//CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA = { 0x00,0x35 };
	public final static byte CIPHERSUITE1 = (byte)0x00;
	public final static byte CIPHERSUITE2 = (byte)0x2F;
   											 
//===============================================================
	
	private boolean debug=true,cOP=false;
	
	private final static byte  FCT_RANDOM            = (byte) 0x02;
	private final static byte  FCT_PRIVATE_ENCRYPT   = (byte) 0x04;
	private final static byte  FCT_PRIVATE_DECRYPT   = (byte) 0x06;
	private final static byte  FCT_PUBLIC_ENCRYPT    = (byte) 0x08;
	private final static byte  FCT_PUBLIC_ENCRYPT_1  = (byte) 0x18; // CA
	private final static byte  FCT_PUBLIC_DECRYPT    = (byte) 0x0A;
	private final static byte  FCT_PUBLIC_DECRYPT_1  = (byte) 0x1A; // CA
	private final static byte  FCT_ENCRYPT           = (byte) 0x0C;
	private final static byte  FCT_DECRYPT           = (byte) 0x0E;
	private final static byte  FCT_TEST_DIGEST       = (byte) 0xC0;
	private final static byte  FCT_SESSION_ID        = (byte) 0xC2;
	private final static byte  FCT_MASTER_SECRET     = (byte) 0xC4;
	private final static byte  FCT_CERT              = (byte) 0x00;
	private final static byte  FCT_CERT_INIT         = (byte) 0x40;
  
	/*
	private final static byte FCT_HMAC_SHA1 =  (byte)0x24 ;
	private final static byte FCT_PRF       =  (byte)0x26 ;
	*/
	private boolean LongFct=false;
	private byte [] Fct_Buffer=null;
	private short Fct_Offset=(short)0;
	private short Fct_Length=(short)0;

	private MessageDigest       md5=null;
	private MessageDigest       sha=null;
	private RSAPrivateCrtKey    rsa_PrivateCrtKey=null;
	private RSAPublicKey        rsa_PublicKey=null;
	private RSAPublicKey        rsa_PublicKey_1024=null;
	private RSAPublicKey        rsa_PublicKey_2048=null;
	
	private RSAPublicKey        rsa_PublicKeyCA=null;
	private Cipher              cipherRSA=null;
	private RandomData          rnd=null ;
	
	private Cipher cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
	private AESKey clientAESKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
	private AESKey serverAESKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
	private short IV_offset = 72;
	private short block_length = 16, padding_length;
	private byte [] Cert;
	private short Cert_Offset, Cert_Length;
	// private byte  [] My_PMK_Key;
	// private short  My_PMK_Key_Offset,My_PMK_Key_Length;
	
 	private  short client_random_offset, server_random_offset;
	
	private final static byte[] ms = {(byte)'m',(byte)'a',(byte)'s',(byte)'t',(byte)'e',(byte)'r',(byte)' ',(byte)'s',(byte)'e',(byte)'c',(byte)'r',(byte)'e',(byte)'t' };
	private final static byte[] ke = {(byte)'k',(byte)'e',(byte)'y',(byte)' ',(byte)'e',(byte)'x',(byte)'p',(byte)'a',(byte)'n',(byte)'s',(byte)'i',(byte)'o',(byte)'n'};
	private final static byte[] cf = {(byte)'c',(byte)'l',(byte)'i',(byte)'e', (byte)'n',(byte)'t',(byte)' ',(byte)'f',(byte)'i',(byte)'n',(byte)'i',(byte)'s',(byte)'h',(byte)'e',(byte)'d' };
	private final static byte[] sf = {(byte)'s',(byte)'e',(byte)'r',(byte)'v',(byte)'e',(byte)'r',(byte)' ',(byte)'f',(byte)'i',(byte)'n',(byte)'i',(byte)'s',(byte)'h',(byte)'e',(byte)'d' };
	private final static byte[] google_cert_CN= {(byte)'w',(byte)'w',(byte)'w',(byte)'.',(byte)'g',(byte)'o',(byte)'o',(byte)'g',(byte)'l',(byte)'e',(byte)'.',(byte)'c',(byte)'o',(byte)'m'};
	private final static byte[] gmail_cert_CN= {(byte)'m',(byte)'a',(byte)'i',(byte)'l',(byte)'.',(byte)'g',(byte)'o',(byte)'o',(byte)'g',(byte)'l',(byte)'e',(byte)'.',(byte)'c',(byte)'o',(byte)'m'};
	private final static byte[] CA_cert_CN = {(byte)'t',(byte)'h',(byte)'a',(byte)'w', (byte)'t',(byte)' ',(byte)'s',(byte)'g',(byte)'c',(byte)' ',(byte)'c',(byte)'a'}; 
	// private final static byte[] root_CA_cert_object = {(byte)'c',(byte)'l',(byte)'a',(byte)'s',(byte)'s',(byte)'3',(byte)' ',(byte)'p',(byte)'u',(byte)'b',(byte)'l',(byte)'i',(byte)'c',(byte)' ',(byte)'p',(byte)'r',(byte)'i',(byte)'m',(byte)'a',(byte)'r',(byte)'y',(byte)' ',(byte)'c',(byte)'e',(byte)'r',(byte)'t',(byte)'i',(byte)'f',(byte)'i',(byte)'c',(byte)'a',(byte)'t',(byte)'i',(byte)'o',(byte)'n',(byte)' ',(byte)'a',(byte)'u',(byte)'t',(byte)'h',(byte)'o',(byte)'r',(byte)'i',(byte)'t',(byte)'h',(byte)'y'};
	// private final static byte[] ee = { (byte)'c',(byte)'l',(byte)'i',(byte)'e',(byte)'n',(byte)'t',(byte)' ',(byte)'E',(byte)'A',(byte)'P',(byte)' ',(byte)'e',(byte)'n',(byte)'c',(byte)'r',(byte)'y', (byte)'p',(byte)'t',(byte)'i',(byte)'o',(byte)'n'}; 
	private final static byte[] login = {(byte)'g',(byte)'i',(byte)'l', (byte)'.',(byte)'s',(byte)'m',(byte)'a',(byte)'r',(byte)'t',(byte)'c',(byte)'a',(byte)'r',(byte)'d',(byte)'@',(byte)'g',(byte)'m',(byte)'a',(byte)'i',(byte)'l',(byte)'.',(byte)'c',(byte)'o',(byte)'m' };
	private final static byte[] password = {(byte)'t',(byte)'e',(byte)'s',(byte)'t',(byte)'1',(byte)'2',(byte)'3',(byte)'4'};
	private final static byte[] form_user = {(byte)'u',(byte)'s',(byte)'e',(byte)'r',(byte)'='};
	private final static byte[] form_pass = {(byte)'p',(byte)'a',(byte)'s',(byte)'s',(byte)'w',(byte)'o',(byte)'r',(byte)'d',(byte)'='};
	
	private final static byte[] CCS = {(byte)0x14,(byte)0x03,(byte)0x01,(byte)0x00,(byte)0x01,(byte)0x01};
	
	private final static byte[] CCS_Server = {(byte)0x14,(byte)0x03,(byte)0x01,
									          (byte)0x00,(byte)0x01,(byte)0x01,
											  (byte)0x16,(byte)0x03,(byte)0x01,
											  (byte)0x00,(byte)0x30};
	
	private final static byte EAP_LENGTH_INCLUDE = (byte)0x80;
	private final static byte EAP_MORE           = (byte)0x40;												
	private final static byte EAP_START          = (byte)0x20;
	private final static byte EAP_ACK            = (byte)0x00;
	
	private final static byte OFFSET_FLAG   = (byte)10;
	private final static byte OFFSET_LENGTH = (byte)11; // 4 bytes
	
	private  final static short heap_size = (short)10000;
	private  final byte  heap[]=new byte[heap_size] ;
	// short fill2= Util.arrayFillNonAtomic(heap,(short)0,(short)10000, (byte)0x00);
	public byte record_buf[]=new byte[(short)(16384+100)]; //record fragment = 16384 bytes (rfc 2246 and 5246)
	// short fill3= Util.arrayFillNonAtomic(record_buf,(short)0,(short) 16484, (byte) 0x00);
		
	private  final short heap_offset=(short)0;
	private  short heap_ptr=(short)0, old_ptr=(short)0,frag_ptr=(short)0;
	private  short LongResponseOffset=(short)0;
	private boolean in_frag=false,out_frag=false,bLongResponse=false;
	
	private static final short READY = (short)-1; 
	private static final byte S_CLIENT_HELLO_TX	= (byte)1;
	private static final byte S_CLIENT_FINISHED_TX	= (byte)80;
	private static final byte S_END			= (byte)100;
	private static final byte RECORD		= (byte)200;
	
	private static byte EAP_TLS_State= S_END; 								   
	
	private byte Client_Hello_Length = (byte)50;
		
	private              short HASH_SIZE	   = (short)16;
	private static final short KEY_SIZE	   = (short)16;
	private static final short RSA_SIZE_CLIENT = (short)128;
	private static final short RSA_SIZE_SERVER = (short)128;
		
	private final static byte[] ClientHello ={ // length = 50
		(byte)0x16,(byte)0x03,(byte)0x01,(byte)0x00,(byte)0x2D,
		(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x29,
		(byte)0x03,(byte)0x01,
		(byte)0x3f,(byte)0xaa,(byte)0x2b,(byte)0x6a,
		(byte)0x08,(byte)0xbd,(byte)0xd2,(byte)0x85,(byte)0xb4,
		(byte)0x3d,(byte)0x1f,(byte)0x3b,(byte)0xc9,(byte)0x71,(byte)0x5f,(byte)0xc9,(byte)0xf8,
		(byte)0x5f,(byte)0xc4,(byte)0x53,(byte)0xfe,(byte)0x58,(byte)0xf3,(byte)0xa9,(byte)0xe0,
		(byte)0x7f,(byte)0xf3,(byte)0x97,(byte)0xcd,(byte)0x65,(byte)0x39,(byte)0x22,
		(byte)0x00,
		(byte)0x00,(byte)0x02,
		CIPHERSUITE1,CIPHERSUITE2,
		(byte)0x01,(byte)0x00};
	
	private byte[]   session_id = new byte[64];
	private byte     session_id_length = (byte)0;
	private boolean  enable_resume = false;
	private boolean  resume=false;
	private short    numct, numct_server,numct_client;
	
	private byte[] pre_master_secret = new byte[48]; 
	private byte[] master_secret     = new byte[80];
	private byte[] key_block         = new byte[120];
	private byte[] finished          = new byte[80];
	private byte[] hash              = new byte[36];
 	 
	private final static short pre_master_secret_off =(short)0;
	private final static short master_secret_off =(short)0;
	private final static short key_block_off =(short)0;
	private final static short finished_off =(short)0;
	private final static short hash_off =(short)0;
	 
	private short con_len=0,con_off=0,con_ptr=0, record_len=0;
	
	private static final short con_size=(short)2000; // 2000 bytes allocated on the RAM = max remaining
	private byte[] con; 
 	private byte[] hmac_temp;
	
	// PRF
	private static byte[]  P ; //= new byte[20];
	private final static short P_off=(short)236; // in con[]
	private static byte [] P_Hash = new byte[128]; // 105= 20 + label_len(21) + seed_len(64)
	private final static short P_Hash_off=(short)0; // or 260 in con[]
	
	// Fct
 	private byte First_Byte;
	
	// ASN.1 Parser
	private static byte  [] ref  = new byte[5];
	private static short [] obj  = new short[2];
	
	private MessageDigest digest=null ;
	
	/**
	* EAP-TLS constructor
	*/
	public methodtls()
	{   con  = JCSystem.makeTransientByteArray(con_size,JCSystem.CLEAR_ON_RESET); // RAM buffer for HMAC and records fragments < 1900 bytes
		P=con;
	}
	
	/**
	* Push data in the heap
	* <br>buf: data buffer
	* <br>offset: data offset
	* <br>length: data length
	*/
	public boolean Push(byte[] buf, short offset, short length)
	{ 
		if ((short)(length+heap_ptr) > heap_size) return false;
		Util.arrayCopyNonAtomic(buf,offset,heap,(short)(heap_offset+heap_ptr),length);
		heap_ptr    = (short)(heap_ptr +length);
		return true;
	}
	  
	// buf[off] -> Record
	// Record version version  msb lsb
	/**
	* Find the next record layer bloc
	* <br>buf: TLS buffer
	* <br>off: offset of the current record in the TLS buffer
	* <br>len: total length of the current record
	* <br>returns the total next record length or -1
	*/
	public static short FindNextRecord(byte[] buf, short off, short len)
	{ 
		short mlen;
		mlen = (short)(5+Util.makeShort(buf[(short)(3+off)],buf[(short)(4+off)]));
		if (mlen >= len) return (short)-1;
		return(mlen);
	}
		
	/**
	* Build a Record Layer Header
	* <br>RH: TLS buffer
	* <br>offset: buffer offset
	* <br>ptcol: protocol number
	* <br>len: length of the message identifier
	* <br>returns the header length (always 5 bytes)
	*/   
	public static short MakeRecordHeader(byte [] RH, short offset,byte ptcol,short len)
	{ 
		RH[offset]            =  ptcol;
		RH[(short)(offset+1)] = (byte)0x03;
		RH[(short)(offset+2)] = (byte)0x01;
		Util.setShort(RH,(short)(offset+3),len);
		return((short)5);
	}
	 
	/**
	* Build an Handshake Header
	* <br>HH: TLS buffer
	* <br>offset: buffer offset
	* <br>message: the message identifier
	* <br>len: length of the message
	* <br>returns the length of the Header
	*/
	public static short MakeHanshakeHeader(byte [] HH, short offset,byte message,short len) 
	{ 
		HH [offset] = message;
		HH [(short)(offset+1)] = (byte)0;
	  
		switch (message)
		{
			case (byte)11: // certificate
				Util.setShort(HH,(short)(offset+2),(short)(len+6));
				HH [(short)(offset+4)]=(byte)0;
				Util.setShort(HH,(short)(offset+5),(short)(len+3));
				HH [(short)(offset+7)]=(byte)0;
				Util.setShort(HH,(short)(offset+8),(short)len);
				return(short)10;
	  
			case (byte)15: // certificate_verify
			case (byte)16: // client_key_exchange
				Util.setShort(HH,(short)(offset+2),(short)(len+2));
				Util.setShort(HH,(short)(offset+4),(short)len);
				return(short)6;
	  
			default:
			Util.setShort(HH,(short)(offset+2),len);
		}
		return(short)4;
	}
	
	public boolean IsLongFct()     { return LongFct;}
	public byte [] Get_Fct_Buffer(){ return Fct_Buffer;}
	public short Get_Fct_Offset()  { return Fct_Offset;}
	public short Get_Fct_Length()  { return Fct_Length;}
	
	public void fct(APDU apdu, byte[] buffer,short len) throws ISOException,CryptoException
	{
		byte P1,P2,P3,mode=(byte)0;
		short adrc;
		P1  = buffer[ISO7816.OFFSET_P1];
		P2  = buffer[ISO7816.OFFSET_P2];
		P3  = buffer[ISO7816.OFFSET_LC]; 
		LongFct = false;
		
		if (  ((P1 & (byte)0xC0) == (byte)0x40) && // INIT
			( ((P1 & (byte)0x3F) == FCT_PUBLIC_DECRYPT)||
			  ((P1 & (byte)0x3F) == FCT_PUBLIC_ENCRYPT)) ) 								  
		{ 
			P1 = (byte)(P1 & (byte)0x3F) ;
			// CLA INS P1 P2 P3 msb-length lsb-length modulus msb-length lsb-lentgh exponent
			len = apdu.setIncomingAndReceive(); 
			len = Util.makeShort(buffer[5],buffer[6]);	
			
			if (len == (short)128)		rsa_PublicKey = rsa_PublicKey_1024;
			else if (len == (short)256)	rsa_PublicKey = rsa_PublicKey_2048;
			else          	     		rsa_PublicKey = null; 
				 
			try {rsa_PublicKey.setModulus(buffer,(short)7,len);}  
			catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
		
			try{rsa_PublicKey.setExponent(buffer,(short)(9+len),
			Util.makeShort(buffer[(short)(7+len)],buffer[(short)(8+len)]));}  
			catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
			 
			return;
		}
		  
		switch (P1)
		{ 
			case FCT_TEST_DIGEST:
				len= Util.makeShort((byte)0,P2);
				len =(short)(len*64);
				if (P3 == (byte)16)
				len= md5.doFinal(heap,heap_offset,len,buffer,(short)0);
				else 
				len=sha.doFinal(heap,heap_offset,len,buffer,(short)0);
				apdu.setOutgoingAndSend((short)0,len); 
				return;

			case FCT_RANDOM:
				len = Util.makeShort((byte)0x00,(byte) buffer[4]);
				rnd.generateData(buffer,(short)0,(short)len);
				apdu.setOutgoingAndSend((short)0,(short)len); 
				return;
		  
			case FCT_CERT_INIT:
			case FCT_CERT:
			  
				LongFct = true;
				Fct_Buffer = Cert;
				Fct_Length = Cert_Length;
				Fct_Offset = Cert_Offset;
				return;
		
			case FCT_PUBLIC_DECRYPT:
			case FCT_PUBLIC_DECRYPT_1:
				mode = Cipher.MODE_DECRYPT;
		 
			case FCT_PUBLIC_ENCRYPT:
			case FCT_PUBLIC_ENCRYPT_1:
			 
				if (mode == (byte)0) mode = Cipher.MODE_ENCRYPT;
				len = apdu.setIncomingAndReceive(); 
				if (len == (short)1) 
				{ 
					First_Byte = buffer[5];
					return;
				}
				 
				if((P1 ==  FCT_PUBLIC_ENCRYPT_1) || (P1 == FCT_PUBLIC_DECRYPT_1) )
				{
					try{cipherRSA.init(rsa_PublicKeyCA,mode);}
					catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
				}
			 
				else
				{
					try{cipherRSA.init(rsa_PublicKey, mode);}
					catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
				}
			 
				if (len == (short)255){
					len = (short)256; adrc=(short)4;buffer[4]=First_Byte;}
				else adrc=(short)5;
			 
				try{len=cipherRSA.doFinal(buffer,adrc,len,buffer, (short)0);}
				catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
				apdu.setOutgoingAndSend((short)0,len); 
				return ;
			 
		
			case FCT_PRIVATE_ENCRYPT:
				mode = Cipher.MODE_ENCRYPT;
			case FCT_PRIVATE_DECRYPT:
				if (mode == (byte)0) mode= Cipher.MODE_DECRYPT;
				len = apdu.setIncomingAndReceive(); 
				try{cipherRSA.init(rsa_PrivateCrtKey,mode);}
				catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
			 			 
				try{len=cipherRSA.doFinal(buffer,(short)5,len,buffer, (short)0);}
				catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
				apdu.setOutgoingAndSend((short)0,len); 
				return ;
			 
			case FCT_SESSION_ID:
				len = apdu.setIncomingAndReceive(); 
				if (len > session_id.length) return;
				session_id_length = P3;
				Util.arrayCopyNonAtomic(buffer,(short)5,session_id,(short)0,len);
				return;
			 
			case FCT_MASTER_SECRET:
				len = apdu.setIncomingAndReceive(); 
				if (len != (short)48) return;
				Util.arrayCopyNonAtomic(buffer,(short)5,master_secret,master_secret_off,(short)48);
				return;	 
			
			default:
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				return ;
		}
	  
	}
	
	public void  reset() 
	{   
		EAP_TLS_State = S_END;
		heap_ptr= frag_ptr = heap_offset;
		in_frag=out_frag=false;
		resume=false;
		digest=sha; // digest default value for the RECORD Layer
		numct=(short)0;
		numct_server=(short)0;
		numct_client=(short)0;
		return;
	}
	
	public short status(){return(0);}
	
	public auth Init(Object Credential)
	{ 
		sha			= ((credentialtls)Credential).sha;
		md5			= ((credentialtls)Credential).md5;
		rsa_PublicKey		= ((credentialtls)Credential).rsa_PublicKey;
		rsa_PublicKey_1024	= ((credentialtls)Credential).rsa_PublicKey_1024;
		rsa_PublicKey_2048	= ((credentialtls)Credential).rsa_PublicKey_2048;
		rsa_PrivateCrtKey	= ((credentialtls)Credential).rsa_PrivateCrtKey;
		cipherRSA		= ((credentialtls)Credential).cipherRSA;
		rnd			= ((credentialtls)Credential).rnd;
		rsa_PublicKeyCA		= ((credentialtls)Credential).rsa_PublicKeyCA;
		Cert_Length		= ((credentialtls)Credential).Cert_Length;
		Cert_Offset		= ((credentialtls)Credential).Cert_Offset;
		Cert			= ((credentialtls)Credential).Cert;
		//Certserver		= ((credentialtls)Credential).Certserver;
		//My_PMK_Key		= ((credentialtls)Credential).PMK_Key;
		//My_PMK_Key_Length	= ((credentialtls)Credential).PMK_Key_Length;
		//My_PMK_Key_Offset	= ((credentialtls)Credential).PMK_Key_Offset;
		//master_secret		= ((credentialtls)Credential).mastersecret;
		debug= ((credentialtls)Credential).step;
		// cOP  = !((credentialtls)Credential).test;
		enable_resume = ((credentialtls)Credential).enable_resume;
		reset();
		return (auth)this ;
	}
	
	public boolean IsLongResponse()
	{ return bLongResponse; }
	
	public short Get_Out_Length()
	{ return heap_size;	}
	
	public short Get_Out_Offset()
	{ return LongResponseOffset;}
	
	public byte[] Get_Out_Buffer()
	{ return heap;	}
	
	public boolean IsFragmented()
	{ return in_frag; }
	
	
	private static void EditByte(byte[] buf,short off,short len){		
	//System.out.println("");
	//tlstest.EditByte(buf,off,len);
	}
	
	/**
	* This method computes a digest (MD5 or SHA1)
	* <br>md: a message digest object
	* <br>msg: data buffer
	* <br>off: data offset
	* <br>len: data length
	* <br>dig: buffer for storing the digest value
	* <br>d_off: offset for storing the digest value
	* <br>returns the digest size (16 or 20 bytes)
	*/
	public static short doFinal(MessageDigest md,byte[]msg, short off, short len, byte[] dig, short d_off)
	{ 
		short size;
		md.reset();
		while (true)
		{ 
			if (len < digest_limit) size=len;
			else					size=digest_limit;
			len = (short)(len-size);
			if (size == digest_limit) md.update(msg,off,size);
			else			   return md.doFinal(msg,off,size,dig,d_off);		
			off = (short)(off+size);	
		}	
	}
	
	//==================================================================
	// CLA INS P1 P2 P3 CODE ID LEN_MSB LEN_LSB TYPE FLAG [LENGTH] .....
	//==================================================================
	
	public short process_eap (byte[] in,short len) throws CryptoException 
	{	
		boolean process=true ;
		short len1=(short)0,len2=(short)0,len3=(short)0;
		byte num=0;
  	    bLongResponse = false;
	 
		if (!in_frag && (len < (short)11)) return(short)0;
	  
		if (!in_frag && (in[OFFSET_FLAG] == EAP_START))
		{	reset();
			if (CIPHERSUITE1==0x00 && CIPHERSUITE2==0x2F)
			{	digest=sha;
			}
			HASH_SIZE=(short)digest.getLength() ;
	 	 	/*if (cOP)
			{ //cOP=true;*/
			Util.arrayCopyNonAtomic(in,(short) 0 ,ClientHello,(short)11,(short)4);
		 	rnd.generateData(ClientHello,(short)15,(short)28);
			Client_Hello_Length= (byte)ClientHello.length ;
			Push(ClientHello,(short)0,(short)Client_Hello_Length);
					
			if (enable_resume && (session_id_length != (byte)0)) 
			{ 
				heap[(short)(heap_offset+43)] = session_id_length;
				heap_ptr = (short)(heap_offset+44);
				Push(session_id,(short)0,(short)session_id_length);
				Push(ClientHello,(short)44,(short)6);
				
				Client_Hello_Length= (byte)(Client_Hello_Length+session_id_length);
			  
				heap[(short)(heap_offset+4)]= (byte)(Client_Hello_Length-(byte)5);
				heap[(short)(heap_offset+8)]= (byte)(Client_Hello_Length-(byte)9);
			}
			/*} else
			{ //cOP=false;
			Push(ClientHelloTest,(short)0,(short)Client_Hello_Length_Test)  ; 
			}*/
		 		  
			EAP_TLS_State = S_CLIENT_HELLO_TX ;
			EAPID = in[6] ; //!!!
		    
			return(EAP_TLS_Output(in,true,false));
		}
		 
		else if (EAP_TLS_State == S_END) 
			return((short)-1);
		
		if (out_frag) // Output q in progress...
		{		
			if (out_frag && (in[OFFSET_FLAG] == EAP_ACK) )
			{ 	// ACK.request received
				EAPID = in[6] ;
				len = EAP_TLS_Output(in,false,false);
				if (len != READY) return(len);
			}
			
		else // Error
		{	EAP_TLS_State = S_END;return(short)-1;}
		}
		
		else 
		{	if (in_frag==false)
			{	EAPID = in[6]; 
				len = EAP_TLS_Input(in,len,true);
			}
			else
				len = EAP_TLS_Input(in,len,false);
		
			if (len != READY) return(len);
		}
	
		while(process)
		{	process=false;
			switch (EAP_TLS_State)
			{	
				case S_CLIENT_HELLO_TX :
					// Record#1, Handshake
					// 16 03 01 xx yy                = 1777
					// +4+6+Cert_Length+ [1499 + 10] = 1509
					// +4+2+128 [Key_exchange]       = 0134
					// +4+2+128 [Verify]             = 0134
					// Record#2, CCS
					// 14 03 01 00 01 01  Change Cipher Spec
					// Record#3, Encrypted Handshake
					// 10 03 01 00 20
					// [encrypted finished message]= 4+12+SHA
					EAP_TLS_State=S_END ;
					len1=old_ptr;
					// resume=false;	
					if (enable_resume &(heap[(short)(len1+43)] != (byte)0)) // session_id_length
					{ 
						if (heap[(short)(len1+43)] <= (byte)session_id.length)
						{	if ((session_id_length == heap[(short)(len1+43)]) &&
							((short)0==Util.arrayCompare(heap,(short)(len1+44),session_id,(short)0,(short)session_id_length)))
							resume=true;
						
						session_id_length = heap[(short)(len1+43)];
						Util.arrayCopy(heap,(short)(len1+44),session_id,(short)0,(short)session_id_length);
						}
					}
					
					if (resume) 
					{ 
						EAP_TLS_State = (byte)90 ;
						process=true; break;
					}  
									
					// Certificate Checking
					//=====================
					// len1=> 1st RecordLayer
					//=======================
					
					// RFC 2246, Section 7.4.2, certificate_list
					// This is a sequence (chain) of X.509v3 certificates. 
					// The sender's certificate must come first in the list. 
					// Each following certificate must directly certify the one preceding it. 
			 
					while(true)
					{ 
						if (heap[len1]==(byte)0x16)
						{	len2 = FindCert(heap,(short)(len1+5),Util.makeShort(heap[(short)(len1+3)],heap[(short)(len1+4)]),(byte)0) ; // Search 1st certficate
							if (len2 != (short)-1) break; 
						}
						// Next Record Header
						len1= (short)(len1+Util.makeShort(heap[(short)(len1+3)],heap[(short)(len1+4)])+5);		
						if (len1 >= heap_ptr) return (short)-1;
					}
							 			
					while(true)
					{	
						if (CheckCertificate(heap,len2,(short)(heap_ptr-old_ptr-len2-5), rsa_PublicKeyCA))
						break;
						// num = (byte)(num+1);// Search 1st certficate
						// len2 = FindCert(heap,(short)(len1+5),Util.makeShort(heap[(short)(len1+3)],heap[(short)(len1+4)]),num) ; 
						// if (len2 == (short)-1) return (short)-1;
						return(short)-1;
					}
		   
					EAP_TLS_State = (byte)50; 
					if (debug) return(short)0;
					
				case (byte)50 :
				
					len1=old_ptr ;//=> Server Hello
					len2=Util.makeShort(heap[(short)(len1+3)],heap[(short)(len1+4)]);
					len1= len3= (short)(len1+len2+5); // => End of Server Hello Message
								
					// Remove Record Header - Client Hello
					// ===================================
					/*if (!cOP)	Util.arrayCopyNonAtomic(heap,(short)0,heap,(short)(heap_offset+5),Client_Hello_Length_Test);
					else*/
					Util.arrayCopyNonAtomic(heap,(short)0,heap,(short)(heap_offset+5),Client_Hello_Length);
					
					// Client-Hello || Server-Hello
					
					// Remove other Record Header
					//===========================
					while(true)
					{	if (len1 >= heap_ptr) break;
						len2=Util.makeShort(heap[(short)(len1+3)],heap[(short)(len1+4)]);
						if (heap[len1]==(byte)0x16)
						{	
							Util.arrayCopyNonAtomic(heap,(short)(len1+5),heap,len3,len2);
							len3= (short)(len2+len3);
						}
						len1 = (short)(len1+len2+5); // => next Record
					}
					
					heap_ptr=len3;
					// All handshake messages are concatenated in
					// [heap_offset+10, heap_ptr[
					client_random_offset= (short)(heap_offset+5+11);
					/*if (!cOP) server_random_offset= (short)(heap_offset+Client_Hello_Length_Test+11) ;
					else*/  	  
					server_random_offset= (short)(heap_offset+Client_Hello_Length+11);
					
					old_ptr = heap_ptr;
					
					// Build the Certificate Message(for client auth)
					//===============================================
					
					// Format the Exchange Key Message
					//=================================
					if	(rsa_PublicKey.getSize() == (short)2048)
						heap_ptr = (short) (heap_ptr + MakeHanshakeHeader(heap,heap_ptr,(byte)16,(short)256));
					else if (rsa_PublicKey.getSize() == (short)1024)
						heap_ptr = (short) (heap_ptr + MakeHanshakeHeader(heap,heap_ptr,(byte)16,(short)128));	
					else {EAP_TLS_State = S_END; return(-1);}
					// pre-master-secret, random number generation
					//============================================
					//if(cOP) 
					rnd.generateData(pre_master_secret,(short)2,(short)46);
					pre_master_secret[0]=(byte)0x03;pre_master_secret[1]=(byte)0x01;
					//else Util.arrayCopyNonAtomic(pre_master_secret_test,(short)0,pre_master_secret,pre_master_secret_off,(short)48);
			 
					// pre-master-secret encryption
					//=============================
					cipherRSA.init(rsa_PublicKey,Cipher.MODE_ENCRYPT);
					len = cipherRSA.doFinal(pre_master_secret,pre_master_secret_off,(short)48,heap,heap_ptr);
					// ========================================
					/*if (cOP) 
					{ */
					Util.setShort(heap,(short)(heap_ptr-2),len);
					heap_ptr = (short) (heap_ptr + len)        ; 
					/*}
					else  Push(client_key_exchange_test,(short)0,(short)client_key_exchange_test.length);*/
								
					EAP_TLS_State = (byte)53 ; 
					if (debug) return(short)0;
		
				case (byte)51 :
							
					// Dual hash calculation, before signing (for client auth)
					//========================================================
					
					EAP_TLS_State = (byte)52 ; 
					if (debug) return(short)0;
						
				case (byte)52 :
						
					// RSA encryption, with our private key (for client auth)
					//=======================================================
					//Build the Verify message
					//========================
								
					EAP_TLS_State = (byte)53; 
					if (debug) return(short)0;
			
				case (byte)53 :
						
					// Master Secret Calculation
					//==========================
					conc_reset();
					conc(heap,client_random_offset,(short)32);
					conc(heap,server_random_offset,(short)32);
					
					PRF(pre_master_secret,pre_master_secret_off,(short)48,
						ms,(short)0,(short)13,
						con,con_off,(short)64,
						(byte)3,(byte)3,master_secret,master_secret_off);
					
					// Master_Secret
					// PRF(pre_master_secret,"master secret",crandom|srandom);
					// EditByte(master_secret,master_secret_off,(short)48);

					EAP_TLS_State = (byte)54 ; 
					if (debug) return(short)0;
			
				case (byte)54 :
			
					// Key Block Calculation
					//======================
					// key_block = PRF(master_secret,"key expansion",srandom|crandom));
					conc_reset();
					conc(heap,server_random_offset,(short)32);
					conc(heap,client_random_offset,(short)32);
					
					PRF(master_secret,master_secret_off,(short)48,
						ke,(short)0,(short)13,
						con,con_off,(short)64,
						(byte)7,(byte)6,key_block,key_block_off);
					
					// EditByte(key_block,key_block_off,(short)104);
					// client_write_MAC_secret = key_block[00,20[
					// server_write_MAC_secret = key_block[20,40[
					// client_write_key        = key_block[40,56[
					// server_write_key        = key_block[56,72[
					// client_write_IV         = key_block[72,88[
					// client_write_IV         = key_block[88,104[
			
					EAP_TLS_State = (byte)55; 
					if (debug) return(short)0;
					   
				case (byte)55 :
			
					// Dual hash for the Client Finished Message
					//==========================================
					doFinal(md5,heap,(short)(heap_offset+10),(short)(heap_ptr-heap_offset-10),con,con_off);
					doFinal(sha,heap,(short)(heap_offset+10),(short)(heap_ptr-heap_offset-10),con,(short)(con_off+16));
					
					// finished-hash_client: 8e58e6f33ce191f4c075560cfe24621330ef01a0b365226d9685727dd531124a46541038
					// EditByte(con,con_off,(short)36);
			
					// finished_data_client = PRF(master_secret,"client finished",finished-handshake-hash)
					//====================================================================================
					PRF(master_secret,master_secret_off,(short)48,
						cf,(short)0,(short)15,
						con,(short)0,(short)36,
						(byte)1,(byte)1,finished,finished_off);
			
					if (resume) 
					{	EAP_TLS_State = (byte)57; 
						if (debug) return(short)0;
						process=true;break;
					}
					
					// Build the client Finished Message
					//==================================
					len=MakeHanshakeHeader(heap,heap_ptr,(byte)20,(short)12);
					Util.arrayCopyNonAtomic(finished,finished_off,heap,(short)(heap_ptr+4),(short)12);
					
					EAP_TLS_State = (byte)56 ; 
					if (debug) return(short)0;
			
				case (byte)56 :
	        
					// Dual hash calculation for the Server Finished Message
					// HASH [heap_offset+10,heap_offset+16[
					//======================================================
					doFinal(md5,heap,(short)(heap_offset+10),(short)(heap_ptr-heap_offset-10+16),hash,(short)(hash_off));
					doFinal(sha,heap,(short)(heap_offset+10),(short)(heap_ptr-heap_offset-10+16),hash,(short)(16+hash_off));
							
					EAP_TLS_State = (byte)57 ; 
					if (debug) return(short)0;
			
				case (byte)57 :
		
					// Build Change Cipher Spec
					//=========================
					Push(CCS,(short)0,(short)6); 
								
					// Build the Handshake Record
					//===========================
					padding_length = (short) (block_length - ((short)(16+HASH_SIZE) % block_length));
					heap_ptr = (short)(heap_ptr+MakeRecordHeader(heap,heap_ptr,(byte)22,(short)(16+HASH_SIZE+padding_length)));
					
					// Build the Client Finished Message Header
					//=========================================
					len=MakeHanshakeHeader(heap,heap_ptr,(byte)20,(short)12);
					
					//Write the Client finished Value
					//==============================
					Util.arrayCopyNonAtomic(finished,(short)0,heap,(short)(heap_ptr+len),(short)12);
					
					// Compute the HMAC
					//=================
					// heap_ptr -> Message, length=16, Protocol = 22(handshake)
					RecordLayerHMAC((byte)22, (short)16,numct_client,false);
					// heap_ptr -> Message || HMAC
									
					// EditByte(heap,heap_ptr,(short)32);
							
					EAP_TLS_State = (byte)58; 
					if (debug) return(short)0;

				case (byte)58 :
			
					// AES key generation
					//===================
					clientAESKey.setKey(key_block,(short)40);
						
					EAP_TLS_State = (byte)59 ; 
					if (debug) return(short)0;
					
				case (byte)59 :
			
					// Encryption Message+HMAC
					//========================
					Util.arrayFillNonAtomic(heap, (short) (heap_ptr + (short)(16+HASH_SIZE)), padding_length, (byte) (padding_length - 1));
					cipherAES.init(clientAESKey, Cipher.MODE_ENCRYPT, key_block, (short) (IV_offset), block_length);
					cipherAES.doFinal(heap, heap_ptr, (short)(16+HASH_SIZE+padding_length), heap, heap_ptr);
					Util.arrayCopyNonAtomic(heap, (short)(heap_ptr+16+HASH_SIZE+padding_length-block_length), key_block, (short)IV_offset, block_length);
					
					//EditByte(heap,heap_ptr,(short)32);
					
					heap_ptr = (short)(heap_ptr+16+HASH_SIZE+padding_length);		
					//len = (short)(10+Cert_Length+6+RSA_SIZE_SERVER+6+RSA_SIZE_CLIENT);
					
					// Format the 2nd Record
					//======================
					if (!resume) 
					{	// len = (short)(10+Cert_Length+6+RSA_SIZE_SERVER+6+RSA_SIZE_CLIENT+6+5+16+HASH_SIZE);
						len = (short)(heap_ptr-old_ptr-27-HASH_SIZE-padding_length);
						MakeRecordHeader(heap,(short)(old_ptr-5),(byte)22,len);
						frag_ptr = (short)(old_ptr-5)  ;
					}
					else 
					{	frag_ptr= old_ptr; 
						EAP_TLS_State = (byte)83; 
						if (debug) return(short)0;
						process=true;break;
					}
		
					EAP_TLS_State = S_CLIENT_FINISHED_TX;
					return(EAP_TLS_Output(in,true,false));		
					//break;
			
				case S_CLIENT_FINISHED_TX:
			
					// 14 03 01 00 01 01   // Change Cipher Spec
					// 16 03 01 00 30      // Encrypted Hanshake Message
					
					// old_ptr  -> Record_Begin
					// heap_ptr -> Record_End
										
					if ((short)(heap_ptr-old_ptr) != (short)(27+HASH_SIZE+padding_length))
						return(short)-1;
					
					if (Util.arrayCompare(heap,old_ptr,CCS_Server,(short)0,(short)10) != (short)0)
						return(short)-1;
					
					heap_ptr = (short)(old_ptr+11);
					// heap_ptr -> message
					
					// Generate the AES Key
					//=====================
					serverAESKey.setKey(key_block,(short) 56);
						
					// Server Finished Message Decryption
					//===================================
					cipherAES.init(serverAESKey, Cipher.MODE_DECRYPT, key_block, (short) (IV_offset+block_length), block_length);
					Util.arrayCopyNonAtomic(heap, (short)(heap_ptr+16+HASH_SIZE+padding_length-block_length), key_block, (short)(IV_offset+block_length), block_length);
					cipherAES.doFinal(heap, heap_ptr, (short)(16+HASH_SIZE+padding_length), heap, heap_ptr);

					// EditByte(heap,heap_ptr,(short)32);
					
					EAP_TLS_State = (byte)81; 
					if (debug) return(short)0;

			
				case (byte)81 :
				
					// Check HMAC 
					//===========
				
					// RecordLayerHMAC(byte ptcol, short message_len,boolean check)
				
					if (!RecordLayerHMAC((byte)22, (short)16,numct_server,true))
					{	EAP_TLS_State = S_END;
						return(-1);
					}

					EAP_TLS_State = (byte)82; 
					if (debug) return(short)0;
							
				case (byte)82 :
				
					// Check Server Finished Data
					// ==========================
					PRF(master_secret,master_secret_off,(short)48,
						sf,(short)0,(short)15,
						hash,hash_off,(short)36,
						(byte)1,(byte)1,finished,finished_off);
						
					if (Util.arrayCompare(finished,finished_off,heap,(short)(heap_ptr+4),(short)12) != (short)0)
					{	EAP_TLS_State = S_END;return(-1);
					}
					EAP_TLS_State = (byte)84; 
					if (debug) return(short)0;

				case (byte)83 :
			
					// PMK Key calculation
					//====================
					/*			
					conc_reset();
					conc(heap,client_random_offset,(short)32);
					conc(heap,server_random_offset,(short)32);
														
					PRF(master_secret,master_secret_off,(short)48,
						ee,(short)0,(short)21,
						con,con_off,(short)64,
						(byte)4,(byte)4,in,(short)0);
					
					Util.arrayCopyNonAtomic(in,(short)0,My_PMK_Key,(short)(My_PMK_Key_Offset+32),(short)32);
					Util.arrayCopyNonAtomic(in,(short)32,My_PMK_Key,My_PMK_Key_Offset,(short)32);
					
					EditByte(My_PMK_Key,My_PMK_Key_Offset,(short)64);*/
			
					EAP_TLS_State = (byte)84;
					if (debug) return(short)0; 
			
				case (byte)84 :
				
					if (!enable_channel) EAP_TLS_State = S_END     ;
					else                 EAP_TLS_State = RECORD ;
					
					if (resume) 
						return(EAP_TLS_Output(in,true,true));	
					
					frag_ptr = heap_ptr;
					return(EAP_TLS_Output(in,false,true));		
			
				case (byte)90 :
		    
					// old_ptr => Server Hello
					len1=heap_ptr ; 
					len2=Util.makeShort(heap[(short)(old_ptr+3)],heap[(short)(old_ptr+4)]);
					len3= (short)(old_ptr+len2+5); // => End of Server Hello Message	
						
					// Remove Record Header - Client Hello
					// ===================================
					/*if (!cOP) Util.arrayCopyNonAtomic(heap,(short)0,heap,(short)(heap_offset+5),Client_Hello_Length_Test);
					else*/      Util.arrayCopyNonAtomic(heap,(short)0,heap,(short)(heap_offset+5),Client_Hello_Length);
			
					client_random_offset= (short)(heap_offset+5+11);
					/*if (!cOP) server_random_offset= (short)(heap_offset+Client_Hello_Length_Test+11) ;
					else*/ server_random_offset= (short)(heap_offset+Client_Hello_Length+11);
					
					// Key Block Calculation
					//======================
					// key_block = PRF(master_secret,"key expansion",srandom|crandom));
					conc_reset();
					conc(heap,server_random_offset,(short)32);
					conc(heap,client_random_offset,(short)32);
					
					PRF(master_secret,master_secret_off,(short)48,
						ke,(short)0,(short)13,
						con,con_off,(short)64,
						(byte)7,(byte)6,key_block,key_block_off);	// produces 120 bytes of output (104 used)
						
					// Dual hash calculation for the Server Finished Message
					// HASH [heap_offset+10,len3[
					//======================================================
					
					doFinal(md5,heap,(short)(heap_offset+10),(short)(len3-heap_offset-10),hash,(short)(hash_off));
					doFinal(sha,heap,(short)(heap_offset+10),(short)(len3-heap_offset-10),hash,(short)(16+hash_off));
									
					// 14 03 01 00 01 01   // Change Cipher Spec
					// 16 03 01 00 30      // Encrypted Hanshake Message
					// len3     -> Record_Begin
					// heap_ptr -> Record_End
									
					if ((short)(heap_ptr-len3) != (short)(27+HASH_SIZE))
					{	EAP_TLS_State = S_END;
						return(short)-1;
					}
					if (Util.arrayCompare(heap,len3,CCS_Server,(short)0,(short)10) != (short)0)
					{	EAP_TLS_State = S_END;
						return(short)-1;
					}
					heap_ptr = (short)(len3+11);
					// heap_ptr -> message
					
					// Generate the AES Key
					//=====================
					serverAESKey.setKey(key_block,(short) 56);
						
					// Server Finished Message Decryption
					//===================================
					cipherAES.init(serverAESKey, Cipher.MODE_DECRYPT, key_block, (short) (IV_offset+block_length), block_length);
					Util.arrayCopyNonAtomic(heap, (short)(heap_ptr+16+HASH_SIZE+1-block_length), key_block, (short)(IV_offset+block_length), block_length);
					cipherAES.doFinal(heap, heap_ptr, (short)(16+HASH_SIZE+16), heap, heap_ptr);
					
					//EditByte(heap,heap_ptr,(short)32);
					EAP_TLS_State = (byte)91; 
						
				case (byte)91 :
			
					// Check HMAC 
					//===========
					
					// RecordLayerHMAC(byte ptcol,short message_len,boolean check)
					if (!RecordLayerHMAC((byte)22,(short)16,numct_server,true))
					{	EAP_TLS_State = S_END;
						return(-1);
					}
					
					EAP_TLS_State = (byte)92 ; 
		
				case (byte)92 :
				
					// Check Server Finished Data
					// ==========================
					PRF(master_secret,master_secret_off,(short)48,
						sf,(short)0,(short)15,
						hash,hash_off,(short)36,
						(byte)1,(byte)1,finished,finished_off);
						
					if (Util.arrayCompare(finished,finished_off,heap,(short)(heap_ptr+4),(short)12) != (short)0)
					{	EAP_TLS_State = S_END;return(-1);
					}
										
					
					heap_ptr= len1 ;
					len1=len3; // -> end of server hello
					
					//=======================
					// Remove Record Header
					//=======================
					while(true)
					{	if (len1 >= heap_ptr) break;
						len2=Util.makeShort(heap[(short)(len1+3)],heap[(short)(len1+4)]);
						if (heap[len1]==(byte)0x16)
						{
							Util.arrayCopyNonAtomic(heap,(short)(len1+5),heap,len3,len2);
							len3= (short)(len2+len3);
						}
						len1 = (short)(len1+len2+5); // => next Record
					}	 
					
					len3 = (short)(len3-HASH_SIZE); // remove HMAC
					old_ptr = heap_ptr=len3;
					// All handshake messages are concatenated in [heap_offset+10, heap_ptr[
					
					EAP_TLS_State = (byte)55; 
					if (debug) return(short)0;
					process=true;break;
			
		
				case RECORD :
									
					if (heap[old_ptr]==(byte)23 && heap[(short)(old_ptr+1)]==(byte)03 && heap[(short)(old_ptr+2)]==(byte)01) // provisional pattern matching
					{ 						
						len= Util.makeShort(heap[(short)(old_ptr+3)],heap[(short)(old_ptr+4)]);
						numct_server=(short)(numct_server+1);
						heap_ptr=frag_ptr=(short)(old_ptr + 5);

						cipherAES.init(serverAESKey, Cipher.MODE_DECRYPT, key_block, (short) (IV_offset+block_length), block_length);
						Util.arrayCopyNonAtomic(heap, (short)(heap_ptr+len-block_length), key_block, (short)(IV_offset+block_length), block_length);
						cipherAES.doFinal(heap, heap_ptr, (short)(len), heap, heap_ptr);
						padding_length = (short) (heap[(short)(heap_ptr+len - 1)] + 1);
						len=(short)(len - padding_length-HASH_SIZE);
						
						if (!RecordLayerHMAC((byte)23,(short)(len),numct_server,true))
						{	EAP_TLS_State = S_END;
							return(-1);
						} 
						
						heap_ptr = (short)((short)heap_ptr+(short)len);
						return(EAP_TLS_Output(in,true,true));	
					}
					
					else if (heap[old_ptr]==(byte)21 && heap[(short)(old_ptr+1)]==(byte)03 && heap[(short)(old_ptr+2)]==(byte)01) //ALERT (21)
					{
						frag_ptr = heap_ptr;
						return(EAP_TLS_Output(in,false,true));	
					}
					
					else 
					{
						len=(short)(record_len-6);
						numct_client=(short)(numct_client+1);
					
						frag_ptr= (short)(old_ptr-5);
						heap_ptr= (short)(old_ptr); 
				
						if (numct_client==1) 
						{				
							fill=fill_form(heap,len,heap_ptr);
							if (fill==false)
							{	EAP_TLS_State = S_END;
								return(-1);		
							}
						} 
						
						padding_length = (short) (block_length - ((short)(len+HASH_SIZE) % block_length));
						MakeRecordHeader(heap,(short)((short)heap_ptr-(short)5),(byte)23,(short)(len+HASH_SIZE+padding_length));
						RecordLayerHMAC((byte)23,(short)len,numct_client,false);

						Util.arrayFillNonAtomic(heap, (short) (heap_ptr+len+HASH_SIZE), padding_length, (byte) (padding_length - 1));
						cipherAES.init(clientAESKey, Cipher.MODE_ENCRYPT, key_block, (short) (IV_offset), block_length);
						cipherAES.doFinal(heap, heap_ptr, (short)(len+HASH_SIZE+padding_length), heap, heap_ptr);
						Util.arrayCopyNonAtomic(heap, (short)(heap_ptr+len+HASH_SIZE+padding_length-block_length), key_block, (short)IV_offset, block_length);
						heap_ptr = (short)(heap_ptr+len+HASH_SIZE+padding_length);

						return(EAP_TLS_Output(in,true,true));			
					}
			}
		}
		return(short)0;
	}
	
	
	private boolean fill=false;
	public boolean fill_form(byte [] buffer, short length, short offset) // provisional static filling for login and password of fixed lengths
	{	short i,k;
		for(i=(short)(offset+length-19); i>(short)offset; i--)
		{
			if(Util.arrayCompare(buffer,(short)(i),form_pass,(short)(0),(short)(form_pass.length))==(short)0)
				Util.arrayCopyNonAtomic(password,(short)(0),buffer,(short)(i+9),(short)password.length);
		
			if(Util.arrayCompare(buffer,(short)(i),form_user,(short)(0),(short)(form_user.length))==(short)0)
			{	Util.arrayCopyNonAtomic(login,(short)(0),buffer,(short)(i+5),(short)login.length);
				return true;
			}
		}
	return false;
	}
	
	private final byte [] num= { (byte)0,(byte)0,(byte)0,(byte)0,
                                 (byte)0,(byte)0,(byte)0,(byte)0 };
	
	//  client_MAC = hmac(client_write_MAC_secret,
	//  						      uint64_seq_num + 
	//   						      ptcol(16) 03 01 00-10 (message_length)+
	//                                message ;	
	// heap_ptr->message
	/**
	* Compute or check the Record Layer HMAC
	* <br>ptcol: the protocol identifier
	* <br>message_len: the message length in the heap, heap_ptr->message
	* <br>number: the counter value
	* <br>check: true for checking false for appending HMAC to the message
	* <br>returns true if no errors occured
	*/
	public boolean RecordLayerHMAC(byte ptcol,short message_len,short number,boolean check)
	{ 	
		short headlen ;
	  	headlen = (short)(5+8);
	  	Util.arrayCopyNonAtomic(heap,(short)(heap_ptr-headlen),con,
							       (short)(con_off+con_size-headlen),headlen);
		heap_ptr = (short) (heap_ptr-headlen);
		Util.setShort(num,(short)6,number);
		Push(num,(short)0,(short)8);
		heap_ptr = (short)(heap_ptr + MakeRecordHeader(heap,heap_ptr,ptcol,message_len));
	             //->message
				
		if (!check)
		{   check=true;
			hmac(key_block,key_block_off,HASH_SIZE,heap,(short)(heap_ptr-headlen),
			(short)(headlen+message_len),digest,
			heap,(short)(heap_ptr+message_len));
		}
	  
		else
		{ 
			hmac(key_block,(short)(key_block_off+HASH_SIZE),HASH_SIZE,
			heap,(short)(heap_ptr-headlen),(short)(headlen+message_len),digest,
			heap,(short)(heap_ptr+message_len+HASH_SIZE));
		   
		if (Util.arrayCompare(heap,(short)(heap_ptr+message_len),heap,
			(short)(heap_ptr+message_len+HASH_SIZE),HASH_SIZE)==(short)0)
			check = true ;
		else 
			check= false;
		}
	 	  
		Util.arrayCopyNonAtomic(con,(short)(con_off+con_size-headlen),heap,
								(short)(heap_ptr-headlen),headlen);
	  
		return(check);
	}
		
	private byte   EAPID;
	private short  FragLen;
	private boolean Ack;
	
	/**
	* Reassembly of Input Data
	* <br>in: APDU buffer (CLA INS P1 P2 P3 CODE IDT LENGTH-MSB LENGTH-LSB TYPE...
	* <br>len: buffer length
	* <br>first: indicates the first APDU associated to an EAP-TLS message
	* <br>returns: 0 if APDU reassembly is in progress, 6 if an EAP-TLS ACK
	* <br>is generated, READY if EAP-TLS message is ready for processing.
	*/
	public short EAP_TLS_Input(byte[] in,short len,boolean first)
	{  
		if (first)  // first fragment of EAP message
		{	EAPID = in[(short)6];
			in_frag=true;
			if (EAP_TLS_State == RECORD)
			{	record_len=(Util.makeShort(in[(short)7],in[(short)8]));
				if ((short)(heap_ptr+record_len+HASH_SIZE+block_length) > heap_size) // heap memory full -> reset 
					heap_ptr = frag_ptr = heap_offset;
			}
		}
		  
		if (first &&(byte)(in[OFFSET_FLAG] & EAP_LENGTH_INCLUDE) == EAP_LENGTH_INCLUDE) // Length include ?
		{	FragLen = Util.makeShort(in[(short)13],in[(short)14]);
			Push(in,(short)(OFFSET_FLAG+4+1), (short)(len-(short)OFFSET_FLAG-(short)5));	
		}
		else if (first)	 // no length	
			Push(in,(short)(OFFSET_FLAG+1),(short)(len-(short)OFFSET_FLAG-(short)1));
		else // APDU fragment
			Push(in,(short)5, (short)(len-5));	
	
		if (first)
		{	if ((byte)(in[OFFSET_FLAG] & EAP_MORE) == EAP_MORE)	Ack = true; // EAP_TLS fragment
			else												Ack = false; 
		}
	   
	    if (in[2] != (byte)0) return (short)0; // APDU Fragment
		 
		in_frag=false; // Last APDU fragment
		
		if (Ack)      // EAP_TLS Fragment ?
		{	in[0] = (byte)2;
			in[1] =  EAPID;
			in[2] = (byte)0;
			in[3] = (byte)6;
			in[4] = (byte)13;
			in[5] = EAP_ACK;
			return(short)6;
		}
		return READY;	
	}
	
	private final static short RESPONSE_MAX_SIZE=(short)240;
	
	/**
	* Fragmentation of output data
	* <br>out: output buffer
	* <br>length: if true length field is appended
	* <br>reset: if true heap is resetted at fragmentation end
	* <br> returns: number of output bytes
	*/
												
	public short EAP_TLS_Output(byte [] out,boolean length,boolean reset)
	{   
		short len,off=(short)0,lenout;
		    
		out_frag = false ;
		lenout=len = (short)(heap_ptr - frag_ptr);
		
		if (len > EAP_FRAGMENT_SIZE) 
		{	lenout= EAP_FRAGMENT_SIZE; 
			out_frag=true;
		}
			
		if (lenout >RESPONSE_MAX_SIZE)
		{	bLongResponse = true;
			out = heap;
			off=(short)(frag_ptr-6);
			if (length) off=(short)(frag_ptr-10);
			LongResponseOffset=off;  
		}
						
		else
		{	if (!length)  
				Util.arrayCopyNonAtomic(heap,frag_ptr,out,(short)(6+off),lenout);
			else
				Util.arrayCopyNonAtomic(heap,frag_ptr,out,(short)(10+off),lenout);
		}
		out[off]            = (byte)2;
		out[(short)(off+1)] =  EAPID;
		out[(short)(off+4)] = (byte)13;
		if (out_frag) out[(short)(off+5)] = EAP_MORE;
		else          out[(short)(off+5)] = (byte)0;
			
		frag_ptr = (short)(frag_ptr+lenout);
			
		if (length)
		{	out[(short)(off+6)] = out[(short)(off+7)] = (byte)0;
			Util.setShort(out,(short)(off+8),len);
			lenout = (short)(lenout+4);
			out[(short)(off+5)] |= EAP_LENGTH_INCLUDE;
		}
					
		lenout = (short)(6+lenout);
		Util.setShort(out,(short)(off+2),lenout);
		
		if (frag_ptr == heap_ptr)
		{	out[(short)(5+off)] &= (byte)0x80;
			out_frag=false;
			if (!reset)	{old_ptr = heap_ptr;}
			else		{old_ptr = heap_ptr = (short)(heap_offset + 16);}
		}
		return lenout;
	}
	
  
	private  static final short BLOCKSIZE =(short)64  ;

    		
	/**
	* RFC 2246 HMAC & pseudo random function section 5. p11,12,13
	* <br>secret: secret buffer
	* <br>secret_off: secret offset
	* <br>secret_leng: secret length
	* <br>label: label buffer
	* <br>label_off: label offset
	* <br>label_len: label length
	* <br>seed: seed buffer
	* <br>seed_off: seed offset
	* <br>seed_len: seed length
	* <br>x_md5: number of HMAC-MD5
	* <br>x_sha1: number of HMAC-SHA1
	* <br>Prf: PRF buffer
	* <br>Prf_off;: PRF offset
	* returns: Prf value
	*/
	public byte[] PRF(byte[] secret, short secret_off, short secret_len,
						byte [] label,short label_off,short label_len,
						byte[] seed,short seed_off,short seed_len,
						byte x_md5,byte x_sha1,byte[] Prf, short Prf_off)                  
	{ 
		short P_Hash_len;
		short i,k;
		Util.arrayCopyNonAtomic(label,label_off,P_Hash,(short)(P_Hash_off+20),label_len);
		Util.arrayCopyNonAtomic(seed , seed_off,P_Hash,(short)(P_Hash_off+20+label_len),seed_len);
	  
		hmac(secret,secret_off,(short)(secret_len/2),
			P_Hash,(short)(P_Hash_off+20),(short)(label_len+seed_len),md5,
			P_Hash,(short)(P_Hash_off+4));
	  
		P_Hash_len = (short)(16+label_len+seed_len);
	   
		for(i=0;i<(short)x_md5;i=(short)(i+1))
		{ 
			hmac(secret,secret_off,(short)(secret_len/2),
				P_Hash,(short)(P_Hash_off+4),P_Hash_len,md5,
				Prf,(short)(Prf_off+(16*i)));
	   
			hmac(secret,secret_off,(short)(secret_len/2),
				P_Hash,(short)(P_Hash_off+4),(short)16,md5,
				P_Hash,(short)(P_Hash_off+4));
		}
	 
		hmac(secret,(short)(secret_off+(secret_len/2)),(short)(secret_len/2),
			P_Hash,(short)(P_Hash_off+20),(short)(label_len+seed_len),sha,
			P_Hash,(short)P_Hash_off);
		
		P_Hash_len = (short)(20+label_len+seed_len);
		x_sha1 = (byte)((byte)20*x_sha1);
	   
		for(i=0;i<(short)x_sha1;i=(short)(i+20))
		{
			hmac(secret,(short)(secret_off+(secret_len/2)),(short)(secret_len/2),
				P_Hash,(short)P_Hash_off,P_Hash_len,sha,
			P,(short)P_off);
		  
			hmac(secret,(short)(secret_off+(secret_len/2)),(short)(secret_len/2),
				P_Hash,(short)P_Hash_off,(short)20,sha,
				P_Hash,(short)P_Hash_off);
		 
			for(k=0;k<20;k=(short)(k+1)) 
				Prf[(short)(Prf_off+k+i)] ^=  P[(short)(P_off+k)];
		}   
	  return(Prf);

	}

	public static short sha1_ct=(short)0,md5_ct=(short)0;

	void count_digest(short size,short len)	
	{	
		short ct ;
  
		len = (short)(len+8);
  		ct = (short)(len/(short)64);
	  	if ( (short)(len%64) != (short)0)
			ct = (short)(ct+1);
	  	if (size ==(short)16) md5_ct = (short)(md5_ct+ct);
		else                  sha1_ct= (short)(sha1_ct+ct);
	}

	/**
	* HMAC Procedure
	*<br>Secret key        : k, k_off, lk
	*<br>Data              : d, d_off, ld
	*<br>Message Digest    : md
	*<br>Output            : out, out_off
	*<br>returns: nothing
	*/
 
	public void  hmac
	( byte []  k,short k_off, short lk,  /*Secret key*/
	byte []  d,short d_off,short ld,     /*data*/
    MessageDigest md,
	byte out[], short out_off)
	{  	     
		short i,DIGESTSIZE ;
		DIGESTSIZE=(short)md.getLength();
		  		   
		if (lk > (short)BLOCKSIZE) 
		{  	md.reset();
            md.doFinal(k,k_off,lk,k,k_off);
            lk = DIGESTSIZE ;
        }
		   
		if(ld < (short)1900)
		{	hmac_temp=con;} else {hmac_temp= record_buf;}
					
        for (i = 0 ; i < lk ; i=(short)(i+1)) 
			hmac_temp[(short)(i+con_off+BLOCKSIZE+DIGESTSIZE)] = (byte)(k[(short)(i+k_off)] ^ (byte)0x36) ;
		Util.arrayFillNonAtomic(hmac_temp,(short)(BLOCKSIZE+DIGESTSIZE+lk+con_off),(short)(BLOCKSIZE-lk),(byte)0x36);
		Util.arrayCopyNonAtomic(d,d_off,hmac_temp,(short)(con_off+BLOCKSIZE+BLOCKSIZE+DIGESTSIZE),ld);
		con_len = (short)(BLOCKSIZE+ld);
		   
		md.reset();
		md.doFinal(hmac_temp,(short)(con_off+BLOCKSIZE+DIGESTSIZE),con_len,hmac_temp,(short)(con_off+BLOCKSIZE));
			
		count_digest((short)md.getLength(),con_len);
		           
		for (i = 0 ; i < lk ; i=(short)(i+1)) 
			hmac_temp[(short)(i+con_off)] = (byte)(k[(short)(i+k_off)] ^ (byte)0x5C) ;
		Util.arrayFillNonAtomic(hmac_temp,(short)(lk+con_off),(short)(BLOCKSIZE-lk),(byte)0x5C);
		con_len = (short)(DIGESTSIZE+BLOCKSIZE);
		md.reset();
		md.doFinal(hmac_temp,con_off,con_len,out,out_off);
		count_digest((short)md.getLength(),con_len);
	}  
   
	/**
	* Concatenation 
    * <br>in: input buffer
    * <br>off: input offset
    * <br>len: input length
    * returns: true if no errors occured
    */
	public boolean conc(byte[] in, short off, short len)
	{	
		short i;
		if ((short)(con_len+len) > con_size)
			return(false);
	 
		Util.arrayCopyNonAtomic(in,off,con,con_ptr,len);
	 	con_ptr = (short)(con_ptr+len);
		con_len = (short)(con_len+len);
		return(true);
	}
   
	/**
    * Concatenation Reset
    */
	public void conc_reset()
	{	con_ptr=  con_off   ;
		con_len = (short) 0 ;
	}
   
	/**
	* Find a certificate in a list of Handshake Messages
	* <br>buf: TLS buffer, ->ptcol 0 msb lsb (first message)
	* <br>off: offset of the first message
	* <br>len: length of the message list
	* <br>num: number of the certificate (0 for the first one)
	* <br>returns: -1 or offset of the certificate (->Certificate Length)
	*/
	public static short FindCert(byte[] buf, short off, short len,byte num)
	{	
		short mlen,ptr;
		byte n=(byte)0;
	    ptr = off;
	  
		while(true)
		{ // ptcol 0 msb lsb
			mlen = Util.makeShort(buf[(short)(2+ptr)],buf[(short)(3+ptr)]);
			if (buf[ptr] == (byte)11) break;
				ptr = (short)(ptr+4+mlen);
			if (ptr >= (short)(off+len)) 
				return(short)-1;
		}
	  
		len = Util.makeShort(buf[(short)(5+ptr)],buf[(short)(6+ptr)]);
		if (mlen != (short)(len+3)) return(short)-1;
			ptr = (short)(ptr+7);
	  
		while(len >0)
		{	mlen = Util.makeShort(buf[(short)(ptr+1)],buf[(short)(ptr+2)]);
			ptr = (short)(ptr+3);  // ->Cert, len
			if (n == num) return ptr ;
			n = (byte)(n+1);
			ptr = (short)(ptr+mlen);
			len = (short)(len-mlen-3);
		}
	
		return (short)-1;
	}

	/**
	* ASN1 utility, node (type) status
	* <br>tree: ASN1 buffer
	* <br>off: ASN1 offset
	* <br>returns: true for constructed type (node)
	*/

	public static boolean isNode(byte[] tree, short off)
	{	if ((tree[off] & (byte)0x20) != (byte)0x20) 
			return (false);
		else                                         
			return (true);	
	}

	/**
	* ASN1 utility, find a node
	* <br>tree: ASN1 buffer
	* <br>off: ASN1 offset
	* <br>len: ASN1 length
	* <br>id: node buffer 
	* <br>n : node length
	* <br>ref: output values ref[0]=offset, ref[1]=length
	* <br>returns: true if the object (id) is found
	* 
	*/

	// 0, 1, 2, 2.0, 2.1 2.2  2.2.0  2.2.2 ...    
	public static boolean FindNode(byte[] tree, short off, short len, byte [] id,byte n, short ref[])
	{	
		byte r=(byte) 0;
		byte f=(byte) 0;
  		n = (byte)(n-1);
		//[off, off+len-1[
  
		while(true)
		{ 	if (!GetValue(tree,off,len,ref))   return(false);
			if (id[r] != f)
			{  
				if (!GetValue(tree,off,len,ref))   return(false);	
				len = (short)(off+len-ref[1]-ref[0]);
				off = (short)(ref[0]+ref[1]);
				f   = (byte)(f+1);
			}
			else // id[r]==f
			{	if (r==n)	return(true);
				if (!isNode(tree,off)) return(false);
				f = (byte)0;
				r = (byte)(r+1);	
				off = ref[0];
				len = ref[1];
			}
		}
	}

	/**
	* ASN1 utility - Get a node value
	* <br>buf: ASN1 buffer
	* <br>off: ASN1 offset
	* <br>len: ASN1 length
	* <br>ref: output value ref[0]=offset, ref[1]=length
	* <br>returns: true if no errors occured
	*/
	public static boolean GetValue(byte [] buf, short off, short len, short [] ref)
	{	
		short tlen;
		byte r=0;
		if (len < (short)2) 
			return false;
		r = buf[(short)(off+1)];
  		if ((short)r >= 0)
		{	tlen = (short) r ;r=(byte)0;
		} 
  		else
		{	r = (byte) (r & (byte)0x7F);
			if ((short)(2+r) > len) return false;
  			if (r == (byte)1) 
				tlen  = Util.makeShort((byte)0,buf[(short)(off+2)]);
			else
				tlen  = Util.makeShort(buf[(short)(off+r)],buf[(short)(off+1+r)]);
		}
	  
		if ((short)(2+r+tlen)> len) return false ;

		ref[1] = tlen ;
		ref[0] = (short)(off+2+r);
		return(true);
	}

	/**
	* Check a Certficate
	* <br>bin: certificate buffer
	* <br>Cert_off: certificate offset
	* <br>Cert_len: certificate length
	* <br>key: certficate object public key
	* <br>CA: Certification Authority public key
	* <br>returns: true if no errors occured
	*/
	public boolean CheckCertificate(byte[] bin, short Cert_off, short Cert_len, RSAPublicKey CA) throws CryptoException
	{ 	
		short len=(short)0; 
		boolean cSHA1=true;
    
		if (!GetValue(bin,Cert_off,Cert_len,obj)) return false ;
		Cert_off = obj[0];
		Cert_len = obj[1];
		/// check subject name
		ref[0] = (byte)0; // path 0.5.4.0.1 corresponds to the field CN of X509 certificates
		ref[1] = (byte)5;
		ref[2] = (byte)4;
		ref[3] = (byte)0;
		ref[4] = (byte)1;
	
		if(!FindNode(bin, Cert_off,Cert_len,ref,(byte)5,obj)) return(false);
		len = Util.arrayCompare(bin,obj[0],gmail_cert_CN,(short)0,obj[1]); // hardcoded for mail.google.com
		if (len != (short)0) return(false);
			
		ref[0] = (byte)0; // root.0.6.1
		ref[1] = (byte)6;
		ref[2] = (byte)1;
	  	   
		if (!FindNode(bin, Cert_off,Cert_len,ref,(byte)3,obj))	return(false);

		ref[0] = (byte)0; ref[1] = (byte)0;  
		if (!FindNode(bin,(short)(obj[0]+1),(short)(obj[1]-1),ref,(byte)2,obj))	return(false);
   
		if (bin[obj[0]] == (byte)0)
		{ 	obj[0] = (short)(obj[0]+1); obj[1] = (short)(obj[1]-1);
		}
   
		try 
		{  	if (obj[1] == (short)128)      rsa_PublicKey = rsa_PublicKey_1024  ;
			else if (obj[1] == (short)256) rsa_PublicKey = rsa_PublicKey_2048  ;
			else                 		   rsa_PublicKey = null; 
   			rsa_PublicKey.setModulus(bin,obj[0],obj[1]);
		} catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
			
		if(!GetValue(bin,(short)(obj[0]+obj[1]),(short)(Cert_len-obj[1]+Cert_off),obj)) return(false);
   		
		try
		{	rsa_PublicKey.setExponent(bin,obj[0],obj[1]);
		} catch (CryptoException e){ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH+e.getReason()));}
   
		ref[0] = (byte)2; // root.2
		if (!FindNode(bin, Cert_off,Cert_len,ref,(byte)1,obj)) return false;
   
		if (bin[obj[0]] == (byte)0)
		{	obj[0] = (short)(obj[0]+1); obj[1] = (short)(obj[1]-1);
		}
   
		// EditByte(bin,obj[0],obj[1]);
 
		if (CA != null)
		{
			cipherRSA.init(CA,Cipher.MODE_DECRYPT);
			len = cipherRSA.doFinal(bin,obj[0],obj[1],con,con_off);
      
			// EditByte(con,con_off,len);
   
			ref[0] = (byte)0; ref[1] = (byte)1;  
			if (!FindNode(con,con_off,len,ref,(byte)2,obj)) return(false);
	   
			if (obj[1] != (short)20) cSHA1= false;
	   
			// EditByte(con,obj[0],obj[1]);
		  
			Util.arrayCopyNonAtomic(con,obj[0],con,con_off,obj[1]);
	   
			ref[0] = (byte)0; // root.0
			if (!FindNode(bin, Cert_off,Cert_len,ref,(byte)1,obj)) return(false);
			obj[1]= (short)(obj[1] + obj[0]-Cert_off); 
			obj[0]= Cert_off;
		  
			if (cSHA1)
			{	sha.reset();
				len=sha.doFinal(bin,obj[0],obj[1],con,(short)(con_off+20));
			}
			else
			{ 	md5.reset();
				len=md5.doFinal(bin,obj[0],obj[1],con,(short)(con_off+16));
			}  
	   		// EditByte(con,(short)(con_off+len),(short)len);
	   		len = Util.arrayCompare(con,con_off,con,(short)(con_off+len),(short)len) ;
	   		if (len != (short)0) return(false);
		}
		return (true);
	}
}
