package com.gsma.iariauth.sample;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;


public class ExtensionUtils {
	
	private final static String EXTENSION = "com.gsma.services.rcs.capability.EXTENSION";
	private final static String SEP = ";";
	
	public static String[] getExtensions(Context context){
		
		try {
			PackageInfo info;
			info = context.getPackageManager().getPackageInfo(context.getPackageName(),PackageManager.GET_META_DATA);
			return info.applicationInfo.metaData.getString(EXTENSION).split(SEP);
		}
		catch (NameNotFoundException e) {
			return null;
		} 				
	}

}
