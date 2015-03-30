package com.gsma.iariauth.sample;

import java.security.MessageDigest;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;


public class FingerprintUtil {
	
	public static String getFingerprint(Context context){
		

		try {
			Signature[] sigs = context.getPackageManager().getPackageInfo(context.getPackageName(),PackageManager.GET_SIGNATURES).signatures;
			if(sigs.length < 1){ 
				return null;
			}

			// take only the first 		
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(sigs[0].toByteArray());
			byte[] digest = md.digest();

			String toRet = "";
			for (int i = 0; i < digest.length; i++) {
				if (i != 0)
					toRet = toRet.concat(":");
				int b = digest[i] & 0xff;
				String hex = Integer.toHexString(b);
				if (hex.length() == 1)
					toRet = toRet.concat("0");
				toRet = toRet.concat(hex);
			}
			return toRet.toUpperCase();
		}
		catch (Exception e) {
			e.printStackTrace();			
		}
		
		return null;
		
	}

}
