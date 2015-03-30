
package com.gsma.rcs.revocator;

import com.gsma.rcs.core.Core;
import com.gsma.rcs.core.ims.ImsModule;
import com.gsma.rcs.core.ims.network.sip.SipManager;
import com.gsma.rcs.core.ims.network.sip.SipMessageFactory;
import com.gsma.rcs.core.ims.protocol.sip.SipDialogPath;
import com.gsma.rcs.core.ims.protocol.sip.SipRequest;
import com.gsma.rcs.core.ims.protocol.sip.SipTransactionContext;
import com.gsma.rcs.core.ims.service.SessionAuthenticationAgent;
import com.gsma.rcs.provider.LocalContentResolver;
import com.gsma.rcs.provider.security.SecurityLog;
import com.gsma.rcs.provider.settings.RcsSettings;
import com.gsma.rcs.utils.logger.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.gsma.rcs.R;

public class Main extends Activity {

    /**
     * The logger
     */
    private final static Logger logger = Logger.getLogger("Revocator");

    private final static String PREFIX_TAG = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.";

    private EditText service, duration, phone;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (logger.isActivated()) {
            logger.info("Start revocator");
        }

        // Set layout
        setContentView(R.layout.revokator);

        // Add button listener
        Button revokeBtn = (Button) findViewById(R.id.revoke);
        revokeBtn.setOnClickListener(revokeBtnListener);

        Spinner selectService = (Spinner) findViewById(R.id.selectService);
        String[] defaultServicesId = getResources().getStringArray(
                R.array.revokator_default_serviceId);
        List<String> both = new ArrayList<String>();
        Collections.addAll(both, defaultServicesId);
        if (SecurityLog.getInstance() != null) {
            Set<String> servicesIds = SecurityLog.getInstance().getSupportedExtensions();
            String[] servicesIdFromCapabilities = SecurityLog.getInstance()
                    .getSupportedExtensions().toArray(new String[servicesIds.size()]);
            Collections.addAll(both, servicesIdFromCapabilities);
        }
        selectService.setAdapter(new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, both.toArray(new String[both.size()])));
        selectService.setOnItemSelectedListener(new OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                service.setText(((TextView) view).getText());
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });

        Spinner selectDuration = (Spinner) findViewById(R.id.selectDuration);
        selectDuration.setAdapter(new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, getResources().getStringArray(
                        R.array.revokator_duration)));
        selectDuration.setOnItemSelectedListener(new OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                duration.setText(((TextView) view).getText());
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });

        Spinner selectPhone = (Spinner) findViewById(R.id.selectPhone);
        selectPhone.setAdapter(new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item,
                getResources().getStringArray(R.array.revokator_phone)));
        selectPhone.setOnItemSelectedListener(new OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                phone.setText(((TextView) view).getText());
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });

        service = (EditText) findViewById(R.id.service);
        service.setText(selectService.getSelectedItem().toString());

        duration = (EditText) findViewById(R.id.duration);
        duration.setText(selectDuration.getSelectedItem().toString());

        phone = (EditText) findViewById(R.id.phone);
        phone.setText(selectPhone.getSelectedItem().toString());

    }

    /**
     * Button callback
     */
    private OnClickListener revokeBtnListener = new OnClickListener() {
        public void onClick(View v) {

            String serviceId = ((EditText) findViewById(R.id.service)).getText().toString();
            String duration = ((EditText) findViewById(R.id.duration)).getText().toString();
            String data = new StringBuilder("(").append(PREFIX_TAG).append(serviceId).append(",")
                    .append(duration).append(")").toString();
            StringBuffer sb = new StringBuffer("<?xml version=\"1.08\" encoding=\"UTF-8\"?>");
            sb.append("<SystemRequest id=\"999\" type=\"urn:gsma:rcs:extension:control\" data=\""
                    + data + "\">");
            sb.append("</SystemRequest>");
            final String xml = sb.toString();

            EditText toView = (EditText) findViewById(R.id.phone);
            final String to = toView.getText().toString();

            Thread t = new Thread() {
                public void run() {
                    Looper.prepare();
                    StringBuilder sipResult = new StringBuilder("Revocator : ");
                    sendSipMessage("tel:" + to, "application/system-request+xml", xml, sipResult);
                    AlertDialog.Builder builder = new AlertDialog.Builder(Main.this);
                    builder.setMessage(sipResult.toString());
                    builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            dialog.cancel();
                        }
                    });
                    AlertDialog alertDlg = builder.create();
                    alertDlg.show();
                    Looper.loop();
                }
            };
            t.start();
        }
    };

    private void sendSipMessage(String to, String contentType, String content, StringBuilder result) {
        if (logger.isActivated()) {
            logger.info("Send a system message for revocation to " + to);
        }

        try {
            // Create authentication agent
            SessionAuthenticationAgent authenticationAgent = new SessionAuthenticationAgent(Core
                    .getInstance().getImsModule());

            // Create a dialog path
            SipDialogPath dialogPath = new SipDialogPath(Core.getInstance().getImsModule()
                    .getSipManager().getSipStack(), Core.getInstance().getImsModule()
                    .getSipManager().getSipStack().generateCallId(), 1, to,
                    ImsModule.IMS_USER_PROFILE.getPublicUri(), to, Core.getInstance()
                            .getImsModule().getSipManager().getSipStack().getServiceRoutePath(),                             
            RcsSettings.createInstance(new LocalContentResolver(getApplicationContext())));

            // Create MESSAGE request
            SipRequest msg = SipMessageFactory.createMessage(dialogPath, contentType, content);

            // Send MESSAGE request
            SipTransactionContext ctx = Core.getInstance().getImsModule().getSipManager()
                    .sendSipMessageAndWait(msg);

            // Wait response
            ctx.waitResponse(SipManager.TIMEOUT);

            // Analyze received message
            if (ctx.getStatusCode() == 407) {
                // 407 response received

                // Set the Proxy-Authorization header
                authenticationAgent.readProxyAuthenticateHeader(ctx.getSipResponse());

                // Increment the Cseq number of the dialog path
                dialogPath.incrementCseq();

                // Create a second MESSAGE request with the right token
                msg = SipMessageFactory.createMessage(dialogPath, contentType, content);

                // Set the Authorization header
                authenticationAgent.setProxyAuthorizationHeader(msg);

                // Send MESSAGE request
                ctx = Core.getInstance().getImsModule().getSipManager().sendSipMessageAndWait(msg);

                // Wait response
                ctx.waitResponse(SipManager.TIMEOUT);

                // Analyze received message
                if ((ctx.getStatusCode() == 200) || (ctx.getStatusCode() == 202)) {
                    // 200 OK response
                    if (logger.isActivated()) {
                        logger.info("Success");
                    }
                    result.append("Succes\nSIP Status Code : ").append(ctx.getStatusCode());
                } else {
                    // Error
                    if (logger.isActivated()) {
                        logger.info("Failed: " + ctx.getStatusCode());
                    }
                    result.append("Failed\nSIP Status Code : ").append(ctx.getStatusCode());
                }
            } else if ((ctx.getStatusCode() == 200) || (ctx.getStatusCode() == 202)) {
                // 200 OK received
                if (logger.isActivated()) {
                    logger.info("Success");
                }
                result.append("Succes\nSIP Status Code : ").append(ctx.getStatusCode());
            } else {
                // Error responses
                if (logger.isActivated()) {
                    logger.info("Failed: " + ctx.getStatusCode());
                }
                result.append("Failed\nSIP Status Code : ").append(ctx.getStatusCode());
            }
        } catch (Exception e) {
            e.printStackTrace();
            if (logger.isActivated()) {
                logger.info("Failed: " + e.getMessage());
            }
            result.append("Failed\n").append(e.getMessage());
        }
    }
}
