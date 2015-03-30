package com.gsma.iariauth.sample;

import java.io.IOException;
import java.io.InputStream;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.RadioButton;
import android.widget.TextView;

import com.gsma.iariauth.validator.PackageProcessor;
import com.gsma.iariauth.validator.ProcessingResult;

public class MainActivity extends Activity {
	
	private final String XML				= ".xml";
	private final String TRUSTSTORE	= "range-root-truststore.bks";
	
	private String fingerPrint = null;
	private Integer[] rbIds = new Integer[]{R.id.radioButton1,R.id.radioButton2,R.id.radioButton3,R.id.radioButton4,R.id.radioButton5};
	
	private BKSTrustStore trustStore = null;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		fingerPrint = FingerprintUtil.getFingerprint(this) ;
		if(fingerPrint == null){
			Log.e(TAG, "Cant not get signature from application package certificate");
		}
		
		Log.d(TAG, "Application fingerprint: " + fingerPrint);
		Log.w(TAG, "Package name '" + getPackageName()+"'");
		
		init();		
	}

	public void onRadioButtonClicked(View view) {
    boolean checked = ((RadioButton) view).isChecked();
    if(checked){
    	clearResult();
    	checkExtension(((RadioButton) view).getText().toString());
    }
   
}
	/**
	 * Init the view with extensions embedded in application package
	 */
	private void init(){
					
		hideRadioButtons();
		
		String[] extensions = ExtensionUtils.getExtensions(this);		
		for(int i=0;i<extensions.length;i++){			
			RadioButton rb =(RadioButton)findViewById(rbIds[i]);
			rb.setVisibility(View.VISIBLE);
			rb.setText(extensions[i]);			
 		}  		
		
		// try lo load trusStore from assets		
		try{
			trustStore = new BKSTrustStore(getAssets().open(TRUSTSTORE));
		}catch(IOException ioe){
			Log.d(TAG, TRUSTSTORE.concat(" not found in assets"));
		}
	}		
	
	/**
	 * Check if  an extension is authorized 
	 * @param extension
	 */
	private void checkExtension(String extension){
			
		InputStream inStream = null;			
		String iariDoc = extension.concat(XML);
		try{
			inStream = getAssets().open(iariDoc);
			appendMessage(iariDoc.concat(" :"));
			appendMessage("");
			
			appendMessage("Ckecking from IARI Tool : ");
			appendMessage(checkSecurityFromIARITool(inStream, trustStore) + "\n" );		
			appendMessage("");
		}  		
		catch(IOException ioe){			
			Log.d(TAG, iariDoc.concat(" not found in assets"));
		}
		finally{
			if(inStream != null){
				try {inStream.close();}catch (IOException e) {}
			}
		}			
	}
			
	/**
	 * 
	 * @param iariDoc
	 * @param trustStore
	 * @param res
	 */
	private String checkSecurityFromIARITool(InputStream iariDoc, BKSTrustStore trustStore){

		// Checking procedure				
		PackageProcessor processor = new PackageProcessor(trustStore, getPackageName(), fingerPrint);
		ProcessingResult result = processor.processIARIauthorization(iariDoc);
		if (result.getStatus() == ProcessingResult.STATUS_OK) {
			return "Extension is authorized";
		}
		else {
			return String.format("%1$s:\n%2$s", 
					new Object[]{"Extension is not authorized",					
					result.getError()});
		}	
	}
	
	private void hideRadioButtons(){				
		for(int i : rbIds){
			findViewById(i).setVisibility(View.INVISIBLE);	
		}
	}
	
	private void clearResult(){
		((TextView) findViewById(R.id.textView1)).setText("");
	}
	
	private void appendMessage(String message){
		((TextView) findViewById(R.id.textView1)).append(message+"\n");
	}

	private static final String TAG = MainActivity.class.getName();
	
	/**
	 * Returns the UID for the installed application
	 * @param packageManager
	 * @param packageName
	 * @return
	 */
	protected String getUidForPackage(PackageManager packageManager, String packageName){
		
		try {
			int packageUid = packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA).uid;
			return String.valueOf(packageUid);
		} catch (NameNotFoundException e) {			
				Log.w(TAG,new StringBuilder("Package name not found in currently installed applications : ").append(packageName).toString());			
		}
		return null;
	}
	
}
