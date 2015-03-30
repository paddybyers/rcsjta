package com.gsma.iariauth.validator;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.gsma.contrib.javax.xml.crypto.dsig.XMLSignature;
import com.gsma.iariauth.validator.IARIAuthDocument.AuthType;
import com.gsma.iariauth.validator.dsig.SignatureInfo;

import java.util.Map;
import java.util.HashMap;
/**
 * A class encapsulating relevant properties of an IARI Authorization document
 */
public class IARIAuthDocument {

	/**
	 * The type of this IARI Authorization
	 */
	public static enum AuthType {
		UNSPECIFIED(0), STANDALONE(1), RANGE(2);
		private int mValue;

		private static Map<Integer,AuthType> mValueToEnum = new HashMap<Integer,AuthType>();
		static {
			for (AuthType entry : AuthType.values()) {
				mValueToEnum.put(entry.toInt(), entry);
			}
		}

		private AuthType(int value) {
			mValue = value;
		}

		public final int toInt() {
			return mValue;
		}

		public static AuthType valueOf(int value) {
			AuthType entry = mValueToEnum.get(value);
			if (entry != null) {
				return entry;
			}
			throw new IllegalArgumentException("No enum const class " + AuthType.class.getName() + "." + value);

		}
	}
	/**
	 * Public members
	 */
	public AuthType authType;
	public String iari;
	public String range;
	public String packageName;
	public String packageSigner;
	public SignatureInfo signature;

	/**
	 * Public methods
	 */
	public String toString() {
		StringBuffer details = new StringBuffer();
		if(authType != null) {
			details.append("authType=");
			details.append(authType.name());
			details.append('\n');
		}

		if(iari != null) {
			details.append("iari=");
			details.append(iari);
			details.append('\n');
		}

		if(range != null) {
			details.append("range=");
			details.append(range);
			details.append('\n');
		}

		if(packageName != null) {
			details.append("packageName=");
			details.append(packageName);
			details.append('\n');
		}

		if(packageSigner != null) {
			details.append("packageSigner=");
			details.append(packageSigner);
			details.append('\n');
		}

		if(signature != null) {
			details.append(signature);
			details.append('\n');
		}

		return details.toString();
	}

	/**
	 * Read an IARI Authorization document from an InputStream.
	 * It is the caller's responsibility to close the stream after this
	 * method has returned.
	 * @param is
	 * @return status, indicating whether or not processing was successful.
	 * See ProcessingResult for result values.
	 */
	public Artifact read(InputStream is) {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			DocumentBuilder db = dbf.newDocumentBuilder();
			doc = db.parse(is);
		} catch (SAXException e) {
			return new Artifact("Unexpected exception parsing IARI Authorization: " + e.getLocalizedMessage());
		} catch (ParserConfigurationException e) {
			return new Artifact("Unexpected exception parsing IARI Authorization: " + e.getLocalizedMessage());
		} catch (IOException e) {
			return new Artifact("Unexpected exception reading IARI Authorization: " + e.getLocalizedMessage());
		}

		/* check encoding */
		String encoding = doc.getXmlEncoding();
		if(encoding != null && !encoding.equalsIgnoreCase(Constants.UTF8)) {
			return new Artifact("Invalid IARI authorization: iari-authorization is not encoded with UTF-8");
		}

		/* find the iari-authorizqtion element */
		NodeList authElements = doc.getElementsByTagNameNS(Constants.IARI_AUTH_NS, Constants.IARI_AUTH_ELT);
		if(authElements.getLength() != 1) {
			return new Artifact("Invalid IARI authorization: invalid number of iari-authorization elements");
		}
		Element authElement = (Element)authElements.item(0);
		if(authElement != doc.getDocumentElement()) {
			return new Artifact("Invalid IARI authorization: iari-authorization is not the root element");
		}

		/* find the iari element */
		NodeList iariElements = doc.getElementsByTagNameNS(Constants.IARI_AUTH_NS, Constants.IARI_ELT);
		if(iariElements.getLength() != 1) {
			return new Artifact("Invalid IARI authorization: invalid number of iari elements");
		}
		iariNode = (Element)iariElements.item(0);
		if(iariNode.getParentNode() != authElement) {
			return new Artifact("Invalid IARI authorization: iari must be a child of iari-authorization");
		}
		iariNode.setIdAttribute(Constants.ID, true);
		iari = iariNode.getTextContent();

		/* find the iari-range element if present */
		NodeList rangeElements = doc.getElementsByTagNameNS(Constants.IARI_AUTH_NS, Constants.IARI_RANGE_ELT);
		int rangeElementCount = rangeElements.getLength();
		boolean hasRangeElement = (rangeElementCount == 1);
		if(rangeElementCount > 1) {
			return new Artifact("Invalid IARI authorization: invalid number of iari-range elements");
		}
		if(hasRangeElement) {
			rangeNode = (Element)rangeElements.item(0);
			if(rangeNode.getParentNode() != authElement) {
				return new Artifact("Invalid IARI authorization: iari-range must be a child of iari-authorization");
			}
			rangeNode.setIdAttribute(Constants.ID, true);
			range = rangeNode.getTextContent();
		}
		authType = hasRangeElement ? AuthType.RANGE : AuthType.STANDALONE;

		/* find the package-name element if present */
		NodeList nameElements = doc.getElementsByTagNameNS(Constants.IARI_AUTH_NS, Constants.PACKAGE_NAME_ELT);
		int nameElementCount = nameElements.getLength();
		if(rangeElementCount > 1) {
			return new Artifact("Invalid IARI authorization: invalid number of package-name elements");
		}
		if(nameElementCount == 1) {
			packageNameNode = (Element)nameElements.item(0);
			if(packageNameNode.getParentNode() != authElement) {
				return new Artifact("Invalid IARI authorization: package-name must be a child of iari-authorization");
			}
			packageNameNode.setIdAttribute(Constants.ID, true);
			packageName = packageNameNode.getTextContent();
		}

		/* find the package-signer element */
		NodeList signerElements = doc.getElementsByTagNameNS(Constants.IARI_AUTH_NS, Constants.PACKAGE_SIGNER_ELT);
		if(signerElements.getLength() != 1) {
			return new Artifact("Invalid IARI authorization: invalid number of package-signer elements");
		}
		packageSignerNode = (Element)signerElements.item(0);
		if(packageSignerNode.getParentNode() != authElement) {
			return new Artifact("Invalid IARI authorization: package-signer must be a child of iari-authorization");
		}
		packageSignerNode.setIdAttribute(Constants.ID, true);
		packageSigner = packageSignerNode.getTextContent();

		/* find the Signature element */
		NodeList signatureElements = doc.getElementsByTagNameNS(XMLSignature.XMLNS, Constants.SIGNATURE_ELT);
		if(signatureElements.getLength() != 1) {
			return new Artifact("Invalid IARI authorization: invalid number of ds:Signature elements");
		}
		signatureNode = (Element)signatureElements.item(0);
		if(signatureNode.getParentNode() != authElement) {
			return new Artifact("Invalid IARI authorization: package-signer must be a child of iari-authorization");
		}

		return null;
	}

	public Document getDocument() { return doc; }
	public Element getIariNode() { return iariNode; }
	public Element getRangeNode() { return rangeNode; }
	public Element getPackageNameNode() { return packageNameNode; }
	public Element getPackageSignerNode() { return packageSignerNode; }
	public Element getSignatureNode() { return signatureNode; }

	/**
	 * Private
	 */
	private Document doc;
	private Element iariNode;
	private Element rangeNode;
	private Element packageNameNode;
	private Element packageSignerNode;
	private Element signatureNode;
}
