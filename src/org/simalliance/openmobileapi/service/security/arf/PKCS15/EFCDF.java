
package org.simalliance.openmobileapi.service.security.arf.PKCS15;

import org.simalliance.openmobileapi.service.security.arf.DERParser;
import org.simalliance.openmobileapi.service.security.arf.SecureElement;
import org.simalliance.openmobileapi.service.security.arf.SecureElementException;
import org.simalliance.openmobileapi.service.Util;
import org.simalliance.openmobileapi.service.security.arf.PKCS15.PKCS15Exception;

import android.util.Log;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * EF_CDF related features
 ***************************************************/
public class EFCDF extends EF {

    public static final String TAG = "SmartcardService ACE ARF";
    // Standardized ID for EF_CDF file
    public static final byte[] EFCDF_PATH = { 0x50,0x03 };
    public static ArrayList<byte[]> x509Bytes = null;
    private short DerIndex, DerSize  = 0;

    public byte[] isx509(byte[] buffer)
    throws PKCS15Exception {

        DerSize = (short)buffer.length;
        x509Bytes = new ArrayList<byte[]>();
        byte[] start =null;
        byte[] size = new byte[4];

        DERParser DER=new DERParser(buffer);
        if (DerIndex==DerSize) return null;
        while(++DerIndex<DerSize) {
            if ( (buffer[DerIndex] == (byte)0x20) && (buffer[DerIndex+1] == (byte)0x03) ) {
                if ( buffer[DerIndex+3] == 0x01) {
                    start = new byte[]{ buffer[DerIndex+4] };
                    size =  new byte[]{ buffer[DerIndex+7],  buffer[DerIndex+8] };
                } else if ( buffer[DerIndex+3] == 0x02) {
                    start = new byte[]{ buffer[DerIndex+4], buffer[DerIndex+5] };
                    size =  new byte[]{ buffer[DerIndex+8],  buffer[DerIndex+9] };
                }

                byte[] Certbuff = new byte[4];
                Log.v(TAG, "Found x509 !!!!  start.length " + start.length);
                if (start.length == 1) {
                    System.arraycopy(start,0,Certbuff,1,start.length);
                    System.arraycopy(size,0,Certbuff,start.length + 1,size.length);
                } else {
                    System.arraycopy(start,0,Certbuff,0,start.length);
                    System.arraycopy(size,0,Certbuff,start.length,size.length);
                }
                Log.v(TAG, "Found x509 !!!!  start after the byte " + byteArrayToHex(start) + " size : " + byteArrayToHex(size));
                x509Bytes.add(Certbuff);
            }
        }
        return null;
    }

    public static ArrayList<byte[]> returnCouples (){
        return x509Bytes;
    }

    public static String byteArrayToHex(byte[] a) {
       StringBuilder sb = new StringBuilder(a.length * 2);
       for(byte b: a)
          sb.append(String.format("%02x", b & 0xff));
       return sb.toString();
    }

    /**
     * Constructor
     * @param secureElement SE on which ISO7816 commands are applied
     */
    public EFCDF(SecureElement handle) {
        super(handle);
    }

    /**
     * Selects and Analyses EF_ODF file
     * @return Path to "EF_DODF" from "DODF Tag" entry;
     *             <code>null</code> otherwise
     */
    public boolean checkCDF()  throws PKCS15Exception,SecureElementException {
        Log.v(TAG,"Analysing EF_CDF...");
        byte[] path = EFCDF_PATH;
        if ( selectFile(path)!= APDU_SUCCESS) {
            Log.v(TAG,"EF_CDF not found!!");
            return false;
        } else {
            isx509(readBinary(0,Util.END));
            return true;
        }
    }

}
