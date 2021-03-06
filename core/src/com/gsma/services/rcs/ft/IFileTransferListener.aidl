package com.gsma.services.rcs.ft;

/**
 * Callback methods for file transfer events
 */
interface IFileTransferListener {
	void onTransferStarted();
	
	void onTransferAborted();

	void onTransferError(in int error);
	
	void onTransferProgress(in long currentSize, in long totalSize);

	void onFileTransferred(in String filename);
	
	// File transfer has been paused
	void onFileTransferPaused();
	
	// File transfer has been resumed
	void onFileTransferResumed();
}