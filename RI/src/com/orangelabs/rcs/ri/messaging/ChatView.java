/*******************************************************************************
 * Software Name : RCS IMS Stack
 *
 * Copyright (C) 2010 France Telecom S.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package com.orangelabs.rcs.ri.messaging;

import java.util.ArrayList;
import java.util.List;

import org.gsma.joyn.JoynServiceListener;
import org.gsma.joyn.chat.ChatMessage;
import org.gsma.joyn.chat.ChatService;
import org.gsma.joyn.contacts.ContactsService;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ListActivity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Vibrator;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnKeyListener;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.orangelabs.rcs.ri.R;
import com.orangelabs.rcs.ri.utils.SmileyParser;
import com.orangelabs.rcs.ri.utils.Smileys;

/**
 * Chat view
 */
public abstract class ChatView extends ListActivity implements OnClickListener, OnKeyListener, JoynServiceListener {	
	/**
	 * Wizz message
	 */
	protected final static String WIZZ_MSG = "((-))";
	
    /**
     * UI handler
     */
	protected Handler handler = new Handler();
    
    /**
     * Progress dialog
     */
	protected Dialog progressDialog = null;
    
    /**
	 * Chat API
	 */
	protected ChatService chatApi;
    
	/**
	 * Message composer
	 */
    protected EditText composeText;
    
    /**
     * Message list adapter
     */
    protected MessageListAdapter msgListAdapter;
    
    /**
	 * Contacts API
	 */
    protected ContactsService contactsApi;    
       
    /**
     * Utility class to manage the is-composing status
     */
    protected IsComposingManager composingManager;
	
	/**
	 * Smileys
	 */
    protected Smileys smileyResources;
	
	/**
	 * Flag indicating that the activity is put on background
	 */
    protected boolean isInBackground = false;
	
	/**
	 * Messages that were received while we were in background as have to be marked as displayed
	 */
    protected List<ChatMessage> imReceivedInBackgroundToBeDisplayed = new ArrayList<ChatMessage>();

	/**
	 * Messages that were received while we were in background as have to be marked as read
	 */
    protected List<ChatMessage> imReceivedInBackgroundToBeRead = new ArrayList<ChatMessage>();
	
	@Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Set layout
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
        setContentView(R.layout.chat_view);
        
        // Set the message list adapter
        msgListAdapter = new MessageListAdapter(this);
        setListAdapter(msgListAdapter);
        
        // Smiley resources
		smileyResources = new Smileys(this);

        // Set message composer callbacks
        composeText = (EditText)findViewById(R.id.userText);
        composeText.setOnClickListener(this);
        composeText.setOnKeyListener(this);
        composeText.addTextChangedListener(mUserTextWatcher);
                
		// Set send button listener
        Button btn = (Button)findViewById(R.id.send_button);
        btn.setOnClickListener(this);
               
        // Instanciate API
        chatApi = new ChatService(getApplicationContext(), this);
        contactsApi = new ContactsService(getApplicationContext(), this);
        
        // Connect API
        chatApi.connect();
        contactsApi.connect();
    }

    @Override
    public void onDestroy() {
    	super.onDestroy();

        // Disconnect API
        chatApi.disconnect();
        contactsApi.disconnect();
    }
    
    @Override
    protected void onPause() {
    	super.onPause();
    	
    	// Update background flag
    	isInBackground = true;
    }
    
    @Override
    protected void onResume() {
    	super.onResume();
    	
    	// Update background flag
    	isInBackground = false;
    	
    	// Mark all messages that were received while we were in background as "displayed" 
    	for (int i=0;i<imReceivedInBackgroundToBeDisplayed.size();i++){
    		ChatMessage msg = imReceivedInBackgroundToBeDisplayed.get(i);
    		markMessageAsDisplayed(msg);
    	}
    	imReceivedInBackgroundToBeDisplayed.clear();
    	
    	// Mark all messages that were received while we were in background as "read" 
    	for (int i=0;i<imReceivedInBackgroundToBeRead.size();i++){
    		ChatMessage msg = imReceivedInBackgroundToBeRead.get(i);
    		markMessageAsDisplayed(msg);
    	}
    	imReceivedInBackgroundToBeRead.clear();
    }
    
    /**
     * Message composer listener
     * 
     * @param v View
     */
    public void onClick(View v) {
        sendText();
    }

    /**
     * Message composer listener
     * 
     * @param v View
     * @param keyCode Key code
     * @event Key event
     */
    public boolean onKey(View v, int keyCode, KeyEvent event) {
        if (event.getAction() == KeyEvent.ACTION_DOWN) {
            switch (keyCode) {
                case KeyEvent.KEYCODE_DPAD_CENTER:
                case KeyEvent.KEYCODE_ENTER:
                    sendText();
                    return true;
            }
        }
        return false;
    }
    
	/**
	 * Hide progress dialog
	 */
    public void hideProgressDialog() {
    	if (progressDialog != null && progressDialog.isShowing()) {
			progressDialog.dismiss();
			progressDialog = null;
		}
    }        
    
    /**
     * Add a message in the message history
     * 
     * @param direction Direction
     * @param contact Contact
     * @param text Text message
     */
    private void addMessageHistory(int direction, String contact, String text) {
		TextMessageItem item = new TextMessageItem(direction, contact, text);
		msgListAdapter.add(item);
    }

    /**
     * Add a notif in the message history
     * 
     * @param notif Notification
     */
    protected void addNotifHistory(String notif) {
		NotifMessageItem item = new NotifMessageItem(notif);
		msgListAdapter.add(item);
    }    
    
    /**
     * Send a text and display it
     */
    private void sendText() {
        String text = composeText.getText().toString();
        if ((text == null) || (text.length() == 0)) {
        	return;
        }

        // Send text message
    	sendMessage(text);
    	
    	// Add text to the message history
        addMessageHistory(MessageItem.OUT, getString(R.string.label_me), text);
        composeText.setText(null);
    }

    /**
     * Send a wizz and display it
     */
    protected void sendWizz() {
		// Send text message
    	sendMessage(WIZZ_MSG);
    	
		// Add text to the message history
        addMessageHistory(MessageItem.OUT, getString(R.string.label_me), getString(R.string.label_chat_wizz));
    }
    
	/**
	 * Display received message
	 * 
	 * @param msg Instant message
	 */
    protected void displayReceivedMessage(ChatMessage msg) {
		String contact = msg.getContact();
		String txt = msg.getMessage();
		if (txt.equals(WIZZ_MSG)) {
	    	txt = getString(R.string.label_chat_wizz);
	        
	        // Vibrate
	        Vibrator vibrator = (Vibrator)getSystemService(Context.VIBRATOR_SERVICE);
	        vibrator.vibrate(600);
		}
        addMessageHistory(MessageItem.IN, contact, txt);
    }

    /**
	 * Add quick text
	 */
    protected void addQuickText() {
    	AlertDialog.Builder builder = new AlertDialog.Builder(this);
    	builder.setTitle(R.string.label_select_quicktext);
    	builder.setCancelable(true);
        builder.setItems(R.array.select_quicktext, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                String[] items = getResources().getStringArray(R.array.select_quicktext);
        		composeText.append(items[which]);
            }
        });
        
        AlertDialog alert = builder.create();
    	alert.show();
    }
    
    /**********************************************************************
     ******************	Deals with isComposing feature ********************
     **********************************************************************/
    
    private final TextWatcher mUserTextWatcher = new TextWatcher(){
		@Override
		public void afterTextChanged(Editable s) {
			// Check if the text is not null.
			// we do not wish to consider putting the edit text back to null (like when sending message), is having activity 
			if (s.length()>0){
				// Warn the composing manager that we have some activity
				composingManager.hasActivity();
			}
		}
		@Override
		public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
		
		@Override
		public void onTextChanged(CharSequence s, int start, int before, int count) {}
    };
    
    /**
	 * Utility class to handle is_typing timers (see RFC3994)  
	 */
	protected class IsComposingManager{

        // Idle time out (in ms)
        private int idleTimeOut = 0;

 		// Active state refresh interval (in ms)
		private final static int ACTIVE_STATE_REFRESH = 60*1000; 

		// Clock handler
		private ClockHandler handler = new ClockHandler();

		// Is composing state
		public boolean isComposing = false;

		// Event IDs
		private final static int IS_STARTING_COMPOSING = 1;
		private final static int IS_STILL_COMPOSING = 2;
		private final static int MESSAGE_WAS_SENT = 3;
		private final static int ACTIVE_MESSAGE_NEEDS_REFRESH = 4;
		private final static int IS_IDLE = 5;

        public IsComposingManager(int timeout) {
            idleTimeOut = timeout;
        }

		// Clock handler class
		private class ClockHandler extends Handler {
			public void handleMessage(Message msg){
				switch(msg.what){
					case IS_STARTING_COMPOSING :{
						// Send a typing status "active"
						ChatView.this.setTypingStatus(true);
	
						// In IDLE_TIME_OUT we will need to send a is-idle status message 
						handler.sendEmptyMessageDelayed(IS_IDLE, idleTimeOut);
	
						// In ACTIVE_STATE_REFRESH we will need to send an active status message refresh
						handler.sendEmptyMessageDelayed(ACTIVE_MESSAGE_NEEDS_REFRESH, ACTIVE_STATE_REFRESH);
						break;
					}    			
					case IS_STILL_COMPOSING :{
						// Cancel the IS_IDLE messages in queue, if there was one
						handler.removeMessages(IS_IDLE);
	
						// In IDLE_TIME_OUT we will need to send a is-idle status message
						handler.sendEmptyMessageDelayed(IS_IDLE, idleTimeOut);
						break;
					}
					case MESSAGE_WAS_SENT :{
						// We are now going to idle state
						composingManager.hasNoActivity();
	
						// Cancel the IS_IDLE messages in queue, if there was one
						handler.removeMessages(IS_IDLE);
	
						// Cancel the ACTIVE_MESSAGE_NEEDS_REFRESH messages in queue, if there was one
						handler.removeMessages(ACTIVE_MESSAGE_NEEDS_REFRESH);
						break;
					}	    			
					case ACTIVE_MESSAGE_NEEDS_REFRESH :{
						// We have to refresh the "active" state
						ChatView.this.setTypingStatus(true);
	
						// In ACTIVE_STATE_REFRESH we will need to send an active status message refresh
						handler.sendEmptyMessageDelayed(ACTIVE_MESSAGE_NEEDS_REFRESH, ACTIVE_STATE_REFRESH);
						break;
					}
					case IS_IDLE :{
						// End of typing
						composingManager.hasNoActivity();
	
						// Send a typing status "idle"
						ChatView.this.setTypingStatus(false);
	
						// Cancel the ACTIVE_MESSAGE_NEEDS_REFRESH messages in queue, if there was one
						handler.removeMessages(ACTIVE_MESSAGE_NEEDS_REFRESH);
						break;
					}
				}
			}
		}

		/**
		 * Edit text has activity
		 */
		public void hasActivity() {
			// We have activity on the edit text
			if (!isComposing){
				// If we were not already in isComposing state
				handler.sendEmptyMessage(IS_STARTING_COMPOSING);
				isComposing = true;
			} else {
				// We already were composing
				handler.sendEmptyMessage(IS_STILL_COMPOSING);
			}
		}

		/**
		 * Edit text has no activity anymore
		 */
		public void hasNoActivity(){
			isComposing = false;
		}

		/**
		 * The message was sent
		 */
		public void messageWasSent(){
			handler.sendEmptyMessage(MESSAGE_WAS_SENT);
		}
	}
	
	/**
	 * Format text with smiley
	 * 
	 * @param txt Text
	 * @return String
	 */
	private CharSequence formatMessageWithSmiley(String txt) {
		SpannableStringBuilder buf = new SpannableStringBuilder();
		if (!TextUtils.isEmpty(txt)) {
			SmileyParser smileyParser = new SmileyParser(txt, smileyResources);
			smileyParser.parse();
			buf.append(smileyParser.getSpannableString(this));
		}
		return buf;
	}	    

	/**
	 * Message item
	 */
	private abstract class MessageItem {
		public final static int IN = 0;
		public final static int OUT = 1;
		public final static int NA = 2;
		
		private int direction;
		
	    private String contact;

	    public MessageItem(int direction, String contact) {
	    	this.direction = direction;
    		this.contact = contact;
	    }
	    
	    public int getDirection() {
	    	return direction;
	    }
	    
	    public String getContact() {
	    	return contact;
	    }
	}	
	
	/**
	 * Text message item
	 */
	private class TextMessageItem extends MessageItem {
	    private String text;
	    
	    public TextMessageItem(int direction, String contact, String text) {
	    	super(direction, contact);
	    	
	    	this.text = text;
	    }
	    
	    public String getText() {
	    	return text;
	    }
	}	

	/**
	 * Notif message item
	 */
	private class NotifMessageItem extends MessageItem {
	    private String text;
	    
	    public NotifMessageItem(String text) {
	    	super(NA, null);
	    	
	    	this.text = text;
	    }
	    
	    public String getText() {
	    	return text;
	    }
	}	

	/**
	 * Message list adapter
	 */
	public class MessageListAdapter extends ArrayAdapter<MessageItem> {
	    private Context context; 

	    public MessageListAdapter(Context context) {
	        super(context, R.layout.chat_view_item);
	        
	        this.context = context;
	    }
	    
	    @Override
	    public View getView(int position, View convertView, ViewGroup parent) {
	        View row = convertView;
	        MessageItemHolder holder = null;
	        if (row == null) {
	            LayoutInflater inflater = LayoutInflater.from(context);
	            row = inflater.inflate(R.layout.chat_view_item, parent, false);
	            holder = new MessageItemHolder();
	            holder.text = (TextView)row.findViewById(R.id.item_text);
	            row.setTag(holder);
	        } else {
	            holder = (MessageItemHolder)row.getTag();
	        }
	        
        	MessageItem item = (MessageItem)getItem(position);
        	String line;
        	if (item.getDirection() == MessageItem.OUT) {
        		line = "[" + getString(R.string.label_me) + "] ";
        	} else {
        		line = "[" + item.getContact() + "] ";
        	}
        	if (item instanceof NotifMessageItem) {
        		NotifMessageItem notifItem = (NotifMessageItem)item;
				holder.text.setText(notifItem.getText());
        	} else {
        		TextMessageItem txtItem = (TextMessageItem)item;
				String txt = txtItem.getText();
				line += formatMessageWithSmiley(txt);
				
				holder.text.setText(line);
        	}

	        return row;
	    }
	    
	    private class MessageItemHolder {
	        TextView text;
	    }
	}
	
    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        switch (keyCode) {
            case KeyEvent.KEYCODE_BACK:
            	// Quit the session
            	quitSession();
                return true;
        }

        return super.onKeyDown(keyCode, event);
    }
    
    /**
     * Load history
     * 
     * @param chatId Chat ID
     */
    protected abstract void loadHistory(String chatId);	

    /**
     * Send message
     * 
     * @param msg Message
     */
    protected abstract void sendMessage(String msg);
    
    /**
     * Mark a message as "displayed"
     * 
     * @param msg Message
     */
    protected abstract void markMessageAsDisplayed(ChatMessage msg);

    /**
     * Mark a message as "read"
     */
    protected abstract void markMessageAsRead(ChatMessage msg);

    /**
     * Quit the session
     */
    protected abstract void quitSession();
    
    /**
     * Update the is composing status
     * 
     * @param isTyping Is compoing status
     */
    protected abstract void setTypingStatus(boolean isTyping);
}
