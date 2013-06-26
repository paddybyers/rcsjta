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
package com.orangelabs.rcs.service.api;

import org.gsma.joyn.ft.FileTransfer;
import org.gsma.joyn.ft.IFileTransfer;
import org.gsma.joyn.ft.IFileTransferListener;

import android.os.RemoteCallbackList;

import com.orangelabs.rcs.core.ims.service.ImsServiceSession;
import com.orangelabs.rcs.core.ims.service.im.filetransfer.FileSharingError;
import com.orangelabs.rcs.core.ims.service.im.filetransfer.FileSharingSession;
import com.orangelabs.rcs.core.ims.service.im.filetransfer.FileSharingSessionListener;
import com.orangelabs.rcs.provider.messaging.RichMessaging;
import com.orangelabs.rcs.service.api.client.eventslog.EventsLogApi;
import com.orangelabs.rcs.utils.PhoneUtils;
import com.orangelabs.rcs.utils.logger.Logger;

/**
 * File transfer implementation
 * 
 * @author Jean-Marc AUFFRET
 */
public class FileTransferImpl extends IFileTransfer.Stub implements FileSharingSessionListener {
	
	/**
	 * Core session
	 */
	private FileSharingSession session;
	
	/**
	 * List of listeners
	 */
	private RemoteCallbackList<IFileTransferListener> listeners = new RemoteCallbackList<IFileTransferListener>();

	/**
	 * Lock used for synchronisation
	 */
	private Object lock = new Object();

	/**
	 * The logger
	 */
	private Logger logger = Logger.getLogger(this.getClass().getName());

	/**
	 * Constructor
	 * 
	 * @param session Session
	 */
	public FileTransferImpl(FileSharingSession session) {
		this.session = session;
		
		session.addListener(this);
	}

	/**
	 * Returns the file transfer ID of the file transfer
	 * 
	 * @return Transfer ID
	 */
	public String getTransferId() {
		return session.getSessionID();
	}
	
	/**
	 * Returns the remote contact
	 * 
	 * @return Contact
	 */
	public String getRemoteContact() {
		return PhoneUtils.extractNumberFromUri(session.getRemoteContact());
	}
	
	/**
     * Returns the complete filename including the path of the file to be transfered
     *
     * @return Filename
     */
	public String getFileName() {
		return session.getContent().getName();
	}

	/**
     * Returns the size of the file to be transferred
     *
     * @return Size in bytes
     */
	public long getFileSize() {
		return session.getContent().getSize();
	}	

    /**
     * Returns the MIME type of the file to be transferred
     * 
     * @return Type
     */
    public String getFileType() {
        return session.getContent().getEncoding();
    }

	/**
	 * Returns the state of the file transfer
	 * 
	 * @return State 
	 */
	public int getState() {
		// TODO
		int state = ServerApiUtils.getSessionState(session);
		switch(state) {
			case SessionState.PENDING:
				return FileTransfer.State.INITIATED;
			
			case SessionState.ESTABLISHED:
				return FileTransfer.State.STARTED;
			
			case SessionState.CANCELLED:
				return FileTransfer.State.INITIATED;
			
			case SessionState.TERMINATED:
				return FileTransfer.State.TRANSFERED;

			default:
				return FileTransfer.State.UNKNOWN;
		}
	}		
		
	/**
	 * Accepts file transfer invitation
	 */
	public void acceptInvitation() {
		if (logger.isActivated()) {
			logger.info("Accept session invitation");
		}
		
		// Accept invitation
		session.acceptSession();
	}
	
	/**
	 * Rejects file transfer invitation
	 */
	public void rejectInvitation() {
		if (logger.isActivated()) {
			logger.info("Reject session invitation");
		}
		
		// Update rich messaging history
  		RichMessaging.getInstance().updateFileTransferStatus(session.getSessionID(), EventsLogApi.STATUS_CANCELED);

  		// Reject invitation
		session.rejectSession(603);
	}

	/**
	 * Aborts the file transfer
	 */
	public void abortTransfer() {
		if (logger.isActivated()) {
			logger.info("Cancel session");
		}
		
		if (session.isFileTransfered()) {
			// File already transfered and session automatically closed after transfer
			return;
		}

		// Abort the session
		session.abortSession(ImsServiceSession.TERMINATION_BY_USER);
	}

	/**
	 * Adds a listener on file transfer events
	 * 
	 * @param listener Listener
	 */
	public void addEventListener(IFileTransferListener listener) {
		if (logger.isActivated()) {
			logger.info("Add an event listener");
		}

    	synchronized(lock) {
    		listeners.register(listener);
    	}
	}
	
	/**
	 * Removes a listener from file transfer
	 * 
	 * @param listener Listener
	 */
	public void removeEventListener(IFileTransferListener listener) {
		if (logger.isActivated()) {
			logger.info("Remove an event listener");
		}

    	synchronized(lock) {
    		listeners.unregister(listener);
    	}
	}
	
    /*------------------------------- SESSION EVENTS ----------------------------------*/
	
	/**
	 * Session is started
	 */
    public void handleSessionStarted() {
    	synchronized(lock) {
			if (logger.isActivated()) {
				logger.info("Session started");
			}
	
	  		// Notify event listeners
			final int N = listeners.beginBroadcast();
	        for (int i=0; i < N; i++) {
	            try {
	            	listeners.getBroadcastItem(i).onTransferStarted();
	            } catch(Exception e) {
	            	if (logger.isActivated()) {
	            		logger.error("Can't notify listener", e);
	            	}
	            }
	        }
	        listeners.finishBroadcast();		
	    }
    }
    
    /**
     * Session has been aborted
     * 
	 * @param reason Termination reason
	 */
    public void handleSessionAborted(int reason) {
    	synchronized(lock) {
			if (logger.isActivated()) {
				logger.info("Session aborted (reason " + reason + ")");
			}
	
			// Update rich messaging history
			RichMessaging.getInstance().updateFileTransferStatus(session.getSessionID(), EventsLogApi.STATUS_CANCELED);
			
	  		// Notify event listeners
			final int N = listeners.beginBroadcast();
	        for (int i=0; i < N; i++) {
	            try {
	            	listeners.getBroadcastItem(i).onTransferAborted();
	            } catch(Exception e) {
	            	if (logger.isActivated()) {
	            		logger.error("Can't notify listener", e);
	            	}
	            }
	        }
	        listeners.finishBroadcast();
	        
	        // Remove session from the list
	        FileTransferServiceImpl.removeFileTransferSession(session.getSessionID());
	    }
    }
    
    /**
     * Session has been terminated by remote
     */
    public void handleSessionTerminatedByRemote() {
    	synchronized(lock) {
			if (logger.isActivated()) {
				logger.info("Session terminated by remote");
			}
	
	  		if (session.isFileTransfered()) {
				// The file has been received, so only remove session from the list
	  			FileTransferServiceImpl.removeFileTransferSession(session.getSessionID());
	  			return;
	  		}
	  		
			// Update rich messaging history
	  		RichMessaging.getInstance().updateFileTransferStatus(session.getSessionID(), EventsLogApi.STATUS_FAILED);
	
	        // Remove session from the list
	        FileTransferServiceImpl.removeFileTransferSession(session.getSessionID());
	    }
    }
    
    /**
     * File transfer error
     * 
     * @param error Error
     */
    public void handleTransferError(FileSharingError error) {
    	synchronized(lock) {
			if (logger.isActivated()) {
				logger.info("Sharing error " + error.getErrorCode());
			}
	
			// Update rich messaging history
	  		RichMessaging.getInstance().updateFileTransferStatus(session.getSessionID(), EventsLogApi.STATUS_FAILED);
			
	  		// Notify event listeners
			final int N = listeners.beginBroadcast();
	        for (int i=0; i < N; i++) {
	            try {
	            	int code;
	            	switch(error.getErrorCode()) {
            			case FileSharingError.SESSION_INITIATION_CANCELLED:
	            			code = FileTransfer.Error.TRANSFER_CANCELLED;
	            			break;
            			case FileSharingError.SESSION_INITIATION_DECLINED:
	            			code = FileTransfer.Error.INVITATION_DECLINED;
	            			break;
	            		case FileSharingError.MEDIA_SAVING_FAILED:
	            			code = FileTransfer.Error.SAVING_FAILED;
	            			break;
	            		case FileSharingError.MEDIA_SIZE_TOO_BIG:
	            			code = FileTransfer.Error.SIZE_TOO_BIG;
	            			break;
	            		case FileSharingError.MEDIA_TRANSFER_FAILED:
	            			code = FileTransfer.Error.TRANSFER_FAILED;
	            			break;
	            		case FileSharingError.UNSUPPORTED_MEDIA_TYPE:
	            			code = FileTransfer.Error.UNSUPPORTED_TYPE;
	            			break;
	            		default:
	            			code = FileTransfer.Error.TRANSFER_FAILED;
	            	}
	            	listeners.getBroadcastItem(i).onTransferError(code);
	            } catch(Exception e) {
	            	if (logger.isActivated()) {
	            		logger.error("Can't notify listener", e);
	            	}
	            }
	        }
	        listeners.finishBroadcast();
	        
	        // Remove session from the list
	        FileTransferServiceImpl.removeFileTransferSession(session.getSessionID());
	    }
    }
    
    /**
	 * File transfer progress
	 * 
	 * @param currentSize Data size transfered 
	 * @param totalSize Total size to be transfered
	 */
    public void handleTransferProgress(long currentSize, long totalSize) {
    	synchronized(lock) {
			if (logger.isActivated()) {
				logger.debug("Sharing progress");
			}
			
			// Update rich messaging history
	  		RichMessaging.getInstance().updateFileTransferProgress(session.getSessionID(), currentSize, totalSize);
			
	  		// Notify event listeners
			final int N = listeners.beginBroadcast();
	        for (int i=0; i < N; i++) {
	            try {
	            	listeners.getBroadcastItem(i).onTransferProgress(currentSize, totalSize);
	            } catch(Exception e) {
	            	if (logger.isActivated()) {
	            		logger.error("Can't notify listener", e);
	            	}
	            }
	        }
	        listeners.finishBroadcast();		
	     }
    }
    
    /**
     * File has been transfered
     * 
     * @param filename Filename associated to the received content
     */
    public void handleFileTransfered(String filename) {
    	synchronized(lock) {
			if (logger.isActivated()) {
				logger.info("Content transfered");
			}
	
			// Update rich messaging history
			RichMessaging.getInstance().updateFileTransferUrl(session.getSessionID(), filename);
	
	  		// Notify event listeners
			final int N = listeners.beginBroadcast();
	        for (int i=0; i < N; i++) {
	            try {
	            	listeners.getBroadcastItem(i).onFileTransfered(filename);
	            } catch(Exception e) {
	            	if (logger.isActivated()) {
	            		logger.error("Can't notify listener", e);
	            	}
	            }
	        }
	        listeners.finishBroadcast();		
	    }	
    }
}
