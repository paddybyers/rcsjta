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

package org.gsma.joyn.session;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.gsma.joyn.JoynContactFormatException;
import org.gsma.joyn.JoynService;
import org.gsma.joyn.JoynServiceException;
import org.gsma.joyn.JoynServiceListener;
import org.gsma.joyn.JoynServiceNotAvailableException;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;

/**
 * This class offers the main entry point to initiate and manage new
 * and existing multimedia sessions. Several applications may
 * connect/disconnect to the API.
 * 
 * @author Jean-Marc AUFFRET
 */
public class MultimediaSessionService extends JoynService {
	/**
	 * API
	 */
	private IMultimediaSessionService api = null;
	
    /**
     * Constructor
     * 
     * @param ctx Application context
     * @param listener Service listener
     */
    public MultimediaSessionService(Context ctx, JoynServiceListener listener) {
    	super(ctx, listener);
    }

    /**
     * Connects to the API
     */
    public void connect() {
    	ctx.bindService(new Intent(IMultimediaSessionService.class.getName()), apiConnection, 0);
    }
    
    /**
     * Disconnects from the API
     */
    public void disconnect() {
    	try {
    		ctx.unbindService(apiConnection);
        } catch(IllegalArgumentException e) {
        	// Nothing to do
        }
    }
    
    /**
     * Returns true if connected to the service, else returns false
     * 
     * @return Boolean
     */
    public boolean isServiceConnected() {
    	return (api != null);
    }

    /**
	 * Service connection
	 */
	private ServiceConnection apiConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {
        	api = IMultimediaSessionService.Stub.asInterface(service);
        	if (serviceListener != null) {
        		serviceListener.onServiceConnected();
        	}
        }

        public void onServiceDisconnected(ComponentName className) {
        	api = null;
        	if (serviceListener != null) {
        		serviceListener.onServiceDisconnected(JoynService.Error.CONNECTION_LOST);
        	}
        }
    };

    /**
     * Initiate a new multimedia session with a remote contact and for a given service.
     * The SDP (Session Description Protocol) parameter is used to describe the supported
     * media. The parameter contact supports the following formats: MSISDN in national or
     * international format, SIP address, SIP-URI or Tel-URI. If the format of the contact
     * is not supported an exception is thrown.
     * 
     * @param serviceId Service ID
     * @param contact Contact
     * @param sdp Local SDP
     * @param listener Multimedia session event listener
     * @return Multimedia session
     * @throws JoynServiceException
	 * @throws JoynContactFormatException
     */
    public MultimediaSession initiateSession(String serviceId, String contact, String sdp,
    		MultimediaSessionListener listener) throws JoynServiceException, JoynContactFormatException {
		if (api != null) {
			try {
				IMultimediaSession sessionIntf = api.initiateSession(serviceId, contact, sdp, listener);
				return new MultimediaSession(sessionIntf);
			} catch(Exception e) {
				throw new JoynServiceException(e.getMessage());
			}
		} else {
			throw new JoynServiceNotAvailableException();
		}
    }    
    
    /**
     * Returns the list of sessions associated to a given service ID
     * 
     * @param serviceId Service ID
     * @return List of sessions
     * @throws JoynServiceException
     */
    public Set<MultimediaSession> getSessions(String serviceId) throws JoynServiceException {
		if (api != null) {
			try {
	    		Set<MultimediaSession> result = new HashSet<MultimediaSession>();
				List<IBinder> mmsList = api.getSessions(serviceId);
				for (IBinder binder : mmsList) {
					MultimediaSession session = new MultimediaSession(IMultimediaSession.Stub.asInterface(binder));
					result.add(session);
				}
				return result;
			} catch(Exception e) {
				throw new JoynServiceException(e.getMessage());
			}
		} else {
			throw new JoynServiceNotAvailableException();
		}
    }    

    /**
     * Returns a current session from its unique session ID
     * 
     * @return Multimedia session or null if not found
     * @throws JoynServiceException
     */
    public MultimediaSession getSession(String sessionId) throws JoynServiceException {
		if (api != null) {
			try {
				return new MultimediaSession(api.getSession(sessionId));
			} catch(Exception e) {
				throw new JoynServiceException(e.getMessage());
			}
		} else {
			throw new JoynServiceNotAvailableException();
		}
    }    
    
    /**
     * Returns a current session from its invitation Intent
     * 
     * @param intent Invitation intent
     * @return Multimedia session or null if not found
     * @throws JoynServiceException
     */
    public MultimediaSession getSessionFor(Intent intent) throws JoynServiceException {
		if (api != null) {
			try {
				String sessionId = intent.getStringExtra(MultimediaSessionIntent.EXTRA_SESSION_ID);
				if (sessionId != null) {
					return getSession(sessionId);
				} else {
					return null;
				}
			} catch(Exception e) {
				throw new JoynServiceException(e.getMessage());
			}
		} else {
			throw new JoynServiceNotAvailableException();
		}
    }     
}