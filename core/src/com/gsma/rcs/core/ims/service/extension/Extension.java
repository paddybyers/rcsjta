
package com.gsma.rcs.core.ims.service.extension;

import com.gsma.rcs.core.ims.network.sip.FeatureTags;

import android.util.SparseArray;

/**
 *
 */
public class Extension {

    /**
     * Define the type of extension
     */
    public static enum Type {
        /** Extension for Mutlimedia Session */
        MULTIMEDIA_SESSION(0),
        /** Extension for application Id */
        APPLICATION_ID(1);
        private int mValue;

        private static SparseArray<Type> mValueToEnum = new SparseArray<Type>();
        static {
            for (Type entry : Type.values()) {
                mValueToEnum.put(entry.toInt(), entry);
            }
        }

        private Type(int value) {
            mValue = value;
        }

        /**
         * Get Type as integer value
         * 
         * @return integer
         */
        public final int toInt() {
            return mValue;
        }

        /**
         * Get Type from integer value
         * 
         * @param value
         * @return Type
         */
        public static Type valueOf(int value) {
            return mValueToEnum.get(value);
        }
    }

    private final String mExtensionName;
    private Type mType;

    /**
     * Public constructor for an Extension
     * 
     * @param extensionName can be serviceId or iari
     * @param type
     */
    public Extension(String extensionName, Type type) {
        super();
        mExtensionName = extensionName;
        mType = type;
    }

    /**
     * Get extension name as Iari
     * 
     * @return String
     */
    public String getExtensionAsIari() {

        if (mExtensionName.startsWith(IARIUtils.COMMON_PREFIX)) {
            return mExtensionName;
        } else if (mExtensionName.startsWith(FeatureTags.FEATURE_RCSE_EXTENSION)) {
            return IARIUtils.COMMON_PREFIX.concat(mExtensionName
                    .substring(FeatureTags.FEATURE_RCSE_EXTENSION.length() + 1));
        } else {
            return IARIUtils.COMMON_PREFIX.concat(mExtensionName);
        }
    }

    /**
     * Get extension name as serviceId
     * 
     * @return String
     */
    public String getExtensionAsServiceId() {

        if (mExtensionName == null) {
            return null;
        }

        if (mExtensionName.startsWith(IARIUtils.COMMON_PREFIX)) {
            return mExtensionName.substring(IARIUtils.COMMON_PREFIX.length());
        } else if (mExtensionName.startsWith(FeatureTags.FEATURE_RCSE_EXTENSION)) {
            return mExtensionName.substring(FeatureTags.FEATURE_RCSE_EXTENSION.length() + 1);
        } else {
            return mExtensionName;
        }
    }

    /**
     * Get type of extension
     * 
     * @return Type
     */
    public Type getType() {
        return mType;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((getExtensionAsIari() == null) ? 0 : getExtensionAsIari().hashCode());
        result = prime * result + ((mType == null) ? 0 : mType.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Extension other = (Extension) obj;
        if (getExtensionAsIari() == null) {
            if (other.getExtensionAsIari() != null)
                return false;
        } else if (!getExtensionAsIari().equals(other.getExtensionAsIari()))
            return false;
        if (mType != other.mType)
            return false;
        return true;
    }

}
