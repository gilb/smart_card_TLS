/* methodstd.java */
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


package openeapsmartcard   ;
  

import javacard.framework.* ;
import javacard.security.*  ;

/**
 * A Generic Method Implementation
 */
public class methodpsk implements auth {
	  /**
	   * Method Initialisation
	   */			
	   public auth Init(Object Credential)
	   { return (auth)this ;}
	   /**
        * Indicates that the response of the method is stored in a private buffer
        */	
		public boolean IsLongResponse()
		{ return false; }
	    /**
	     * Returns the response buffer length
	    */
		public short Get_Out_Length()
		{ return (short)0 ;	}
	    /**
	     * Returns the response buffer offset
	    */
		public short Get_Out_Offset()
		{ return (short)0;}
	    /**
	     * Returns the response buffer
	    */
		public byte[] Get_Out_Buffer()
		{ return (byte[])null ;	}
		/**
	     * Fragmentation in progress
	     */
		public boolean IsFragmented()
		{ return false ; }
	    /**
	     * Indicates that the response of a function is stored in a private buffer
	     */
		public boolean IsLongFct()
		{ return false; }	
	    /**
	     * Returns a function buffer length
	     */
		public short Get_Fct_Length()
		{ return (short)0 ;	}
	    /**
	     * Returns a function buffer offset
	     */
		public short Get_Fct_Offset()
		{ return (short)0;}
	    /**
	     * Returns a function buffer length
	    */
		public byte[] Get_Fct_Buffer()
		{ return (byte[])null ;	}
	
	    /**
	     * Method Processing
	     * <br>in:  incoming APDU buffer
	     * <br> CLA INS P1 P2 P3 CODE ID LEN_MSB LEN_LSB TYPE FLAG [LENGTH]
	     * <br>len: length of the incoming APDU
	     * <br>Returns
	     * <br>-length of the response
	     * <br>-negative value if an error occured
	    */
		public short process_eap (byte[] in,short len) throws CryptoException 
		{ return(short)-1 ;	}
	    /**
	     * Method functions
	     * <br>apdu: incoming APDU
	     * <br>in: buffer associated to the incoming APDU
	     * <br>len: P3 value
	     */ 
		public  void fct (APDU apdu, byte[] in,short len) throws CryptoException, ISOException 
		{ return ;	}
        /**
	     * Resets the method
	     */
		public void  reset() {return; }
		/**
	     * Gets the method status
	     */
		public short status(){return(0);}
}
