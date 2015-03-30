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

package com.gsma.rcs.provider.security;

import com.gsma.rcs.utils.DatabaseUtils;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.Uri;
import android.text.TextUtils;

/**
 * Security provider
 * 
 * @author yplo6403
 */
public class SecurityProvider extends ContentProvider {
    // Database tables
    private static final String TABLE_CERT = "cert";
    private static final String TABLE_AUTH = "auth";
    private static final String TABLE_REV = "rev";

    private static final String CERT_SELECT_WITH_ID_ONLY = CertificateData.KEY_ID.concat("=?");

    private static final String AUTH_SELECT_WITH_ID_ONLY = AuthorizationData.KEY_ID.concat("=?");

    private static final String REV_SELECT_WITH_ID_ONLY = RevocationData.KEY_ID.concat("=?");

    private static final String DATABASE_NAME = "security.db";

    private static final UriMatcher sUriMatcher;
    static {
        sUriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
        sUriMatcher.addURI(CertificateData.CONTENT_URI.getAuthority(), CertificateData.CONTENT_URI
                .getPath().substring(1), UriType.Certificate.CERT);
        sUriMatcher.addURI(CertificateData.CONTENT_URI.getAuthority(), CertificateData.CONTENT_URI
                .getPath().substring(1).concat("/*"), UriType.Certificate.CERT_WITH_ID);
        sUriMatcher.addURI(AuthorizationData.CONTENT_URI.getAuthority(),
                AuthorizationData.CONTENT_URI.getPath().substring(1), UriType.Authorization.AUTH);
        sUriMatcher.addURI(AuthorizationData.CONTENT_URI.getAuthority(),
                AuthorizationData.CONTENT_URI.getPath().substring(1).concat("/*"),
                UriType.Authorization.AUTH_WITH_ID);
        sUriMatcher.addURI(RevocationData.CONTENT_URI.getAuthority(), RevocationData.CONTENT_URI
                .getPath().substring(1), UriType.Revocation.REV);
        sUriMatcher.addURI(RevocationData.CONTENT_URI.getAuthority(), RevocationData.CONTENT_URI
                .getPath().substring(1).concat("/*"), UriType.Revocation.REV_WITH_ID);

    }

    // Class used to differentiate between the different URI requests
    private static final class UriType {
        private static final class Certificate {
            private static final int CERT = 1;

            private static final int CERT_WITH_ID = 2;
        }

        private static final class Authorization {
            private static final int AUTH = 3;

            private static final int AUTH_WITH_ID = 4;
        }

        private static final class Revocation {
            private static final int REV = 5;

            private static final int REV_WITH_ID = 6;
        }

    }

    private static final class CursorType {
        private static final class Certificate {
            private static final String TYPE_DIRECTORY = "vnd.android.cursor.dir/cert";

            private static final String TYPE_ITEM = "vnd.android.cursor.item/cert";
        }

        private static final class Authorization {
            private static final String TYPE_DIRECTORY = "vnd.android.cursor.dir/auth";

            private static final String TYPE_ITEM = "vnd.android.cursor.item/auth";
        }

        private static final class Revocation {
            private static final String TYPE_DIRECTORY = "vnd.android.cursor.dir/rev";

            private static final String TYPE_ITEM = "vnd.android.cursor.item/rev";
        }
    }

    /**
     * Helper class for opening, creating and managing database version control
     */
    private static class DatabaseHelper extends SQLiteOpenHelper {
        private static final int DATABASE_VERSION = 4;

        public DatabaseHelper(Context ctx) {
            super(ctx, DATABASE_NAME, null, DATABASE_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            // @formatter:off
			db.execSQL(new StringBuilder("CREATE TABLE IF NOT EXISTS ").append(TABLE_CERT).append("(")
					.append(CertificateData.KEY_ID).append(" INTEGER PRIMARY KEY AUTOINCREMENT,")
					.append(CertificateData.KEY_IARI_RANGE).append(" TEXT NOT NULL,")
                    .append(CertificateData.KEY_CERT).append(" TEXT NOT NULL,")
                    .append("UNIQUE(").append(CertificateData.KEY_IARI_RANGE).append(",").append(CertificateData.KEY_CERT)
                    .append("))").toString());
			
			 db.execSQL(new StringBuilder("CREATE INDEX ").append(CertificateData.KEY_IARI_RANGE)
	                    .append("_idx").append(" ON ").append(TABLE_CERT).append("(")
	                    .append(CertificateData.KEY_IARI_RANGE).append(")").toString());
			 
			 db.execSQL(new StringBuilder("CREATE INDEX ").append(CertificateData.KEY_IARI_RANGE)
	                    .append("_").append(CertificateData.KEY_CERT).append("_idx").append(" ON ").append(TABLE_CERT).append("(")
	                    .append(CertificateData.KEY_IARI_RANGE).append(",")
	                    .append(CertificateData.KEY_CERT).append(")").toString());
			 			 
			 db.execSQL(new StringBuilder("CREATE TABLE IF NOT EXISTS ").append(TABLE_AUTH).append("(")
					 	.append(AuthorizationData.KEY_ID).append(" INTEGER PRIMARY KEY AUTOINCREMENT,")
					 	.append(AuthorizationData.KEY_PACK_UID).append(" INTEGER NOT NULL,")
					 	.append(AuthorizationData.KEY_PACK_NAME).append(" TEXT NOT NULL,")
					 	.append(AuthorizationData.KEY_AUTH_TYPE).append(" INTEGER NOT NULL,")
						.append(AuthorizationData.KEY_IARI).append(" TEXT NOT NULL,")
						.append(AuthorizationData.KEY_EXT_TYPE).append(" INTEGER NOT NULL,")
	                    .append(AuthorizationData.KEY_SIGNER).append(" TEXT,")
	                    .append(AuthorizationData.KEY_RANGE).append(" TEXT,")
	                    .append("UNIQUE(").append(AuthorizationData.KEY_IARI)
	                    .append(") ON CONFLICT REPLACE)").toString());
			 
			 db.execSQL(new StringBuilder("CREATE INDEX ").append(AuthorizationData.KEY_PACK_UID)
	                    .append("_").append(AuthorizationData.KEY_IARI).append("_idx").append(" ON ").append(TABLE_AUTH).append("(")	                    
	                    .append(AuthorizationData.KEY_PACK_UID).append(",")
	                    .append(AuthorizationData.KEY_IARI).append(")").toString());
			 db.execSQL(new StringBuilder("CREATE INDEX ").append(AuthorizationData.KEY_PACK_UID)
	                    .append("_").append("_idx").append(" ON ").append(TABLE_AUTH).append("(")	                    
	                    .append(AuthorizationData.KEY_PACK_UID).append(")").toString());
			 db.execSQL(new StringBuilder("CREATE INDEX ").append(AuthorizationData.KEY_IARI)
	                    .append("_").append("_idx").append(" ON ").append(TABLE_AUTH).append("(")	                    
	                    .append(AuthorizationData.KEY_IARI).append(")").toString());
			 
			 db.execSQL(new StringBuilder("CREATE TABLE IF NOT EXISTS ").append(TABLE_REV).append("(")
					 	.append(RevocationData.KEY_ID).append(" INTEGER PRIMARY KEY AUTOINCREMENT,")
					 	.append(RevocationData.KEY_SERVICE_ID).append(" TEXT NOT NULL,")
					 	.append(RevocationData.KEY_DURATION).append(" INTEGER NOT NULL,")
	                    .append("UNIQUE(").append(RevocationData.KEY_SERVICE_ID)
	                    .append(") ON CONFLICT REPLACE)").toString());
			 
			 db.execSQL(new StringBuilder("CREATE INDEX ").append(RevocationData.KEY_SERVICE_ID)
	                    .append("_idx").append(" ON ").append(TABLE_REV).append("(")
	                    .append(RevocationData.KEY_SERVICE_ID).append(")").toString());
			 
			// @formatter:on
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int currentVersion) {
            db.execSQL("DROP TABLE IF EXISTS ".concat(TABLE_CERT));
            db.execSQL("DROP TABLE IF EXISTS ".concat(TABLE_AUTH));
            db.execSQL("DROP TABLE IF EXISTS ".concat(TABLE_REV));
            onCreate(db);
        }
    }

    private SQLiteOpenHelper mOpenHelper;

    private String getCertSelectionWithId(String selection) {
        if (TextUtils.isEmpty(selection)) {
            return CERT_SELECT_WITH_ID_ONLY;

        }
        return new StringBuilder("(").append(CERT_SELECT_WITH_ID_ONLY).append(") AND (")
                .append(selection).append(")").toString();
    }

    private String[] getCertSelectionArgsWithId(String[] selectionArgs, String id) {
        String[] idSelectionArg = new String[] {
            id
        };
        if (selectionArgs == null) {
            return idSelectionArg;

        }
        return DatabaseUtils.appendSelectionArgs(idSelectionArg, selectionArgs);
    }

    private String getAuthSelectionWithId(String selection) {
        if (TextUtils.isEmpty(selection)) {
            return AUTH_SELECT_WITH_ID_ONLY;

        }
        return new StringBuilder("(").append(AUTH_SELECT_WITH_ID_ONLY).append(") AND (")
                .append(selection).append(")").toString();
    }

    private String[] getAuthSelectionArgsWithId(String[] selectionArgs, String id) {
        String[] idSelectionArg = new String[] {
            id
        };
        if (selectionArgs == null) {
            return idSelectionArg;

        }
        return DatabaseUtils.appendSelectionArgs(idSelectionArg, selectionArgs);
    }

    private String getRevocationSelectionWithId(String selection) {
        if (TextUtils.isEmpty(selection)) {
            return REV_SELECT_WITH_ID_ONLY;

        }
        return new StringBuilder("(").append(REV_SELECT_WITH_ID_ONLY).append(") AND (")
                .append(selection).append(")").toString();
    }

    private String[] getRevocationSelectionArgsWithId(String[] selectionArgs, String id) {
        String[] idSelectionArg = new String[] {
            id
        };
        if (selectionArgs == null) {
            return idSelectionArg;

        }
        return DatabaseUtils.appendSelectionArgs(idSelectionArg, selectionArgs);
    }

    @Override
    public boolean onCreate() {
        mOpenHelper = new DatabaseHelper(getContext());
        return true;
    }

    @Override
    public String getType(Uri uri) {
        switch (sUriMatcher.match(uri)) {
            case UriType.Certificate.CERT:
                return CursorType.Certificate.TYPE_DIRECTORY;

            case UriType.Certificate.CERT_WITH_ID:
                return CursorType.Certificate.TYPE_ITEM;

            case UriType.Authorization.AUTH:
                return CursorType.Authorization.TYPE_DIRECTORY;

            case UriType.Authorization.AUTH_WITH_ID:
                return CursorType.Authorization.TYPE_ITEM;

            case UriType.Revocation.REV:
                return CursorType.Revocation.TYPE_DIRECTORY;

            case UriType.Revocation.REV_WITH_ID:
                return CursorType.Revocation.TYPE_ITEM;

            default:
                throw new IllegalArgumentException(new StringBuilder("Unsupported URI ")
                        .append(uri).append("!").toString());
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sort) {
        Cursor cursor = null;
        try {
            switch (sUriMatcher.match(uri)) {
                case UriType.Certificate.CERT_WITH_ID:
                    String id = uri.getLastPathSegment();
                    selection = getCertSelectionWithId(selection);
                    selectionArgs = getCertSelectionArgsWithId(selectionArgs, id);
                    /* Intentional fall through */
                case UriType.Certificate.CERT:
                    SQLiteDatabase db = mOpenHelper.getReadableDatabase();
                    cursor = db.query(TABLE_CERT, projection, selection, selectionArgs, null, null,
                            sort);
                    cursor.setNotificationUri(getContext().getContentResolver(), uri);
                    return cursor;

                case UriType.Authorization.AUTH_WITH_ID:
                    String iari = uri.getLastPathSegment();
                    selection = getAuthSelectionWithId(selection);
                    selectionArgs = getAuthSelectionArgsWithId(selectionArgs, iari);
                    /* Intentional fall through */
                case UriType.Authorization.AUTH:
                    db = mOpenHelper.getReadableDatabase();
                    cursor = db.query(TABLE_AUTH, projection, selection, selectionArgs, null, null,
                            sort);
                    cursor.setNotificationUri(getContext().getContentResolver(), uri);
                    return cursor;
                    //
                case UriType.Revocation.REV_WITH_ID:
                    String revId = uri.getLastPathSegment();
                    selection = getRevocationSelectionWithId(selection);
                    selectionArgs = getRevocationSelectionArgsWithId(selectionArgs, revId);
                    /* Intentional fall through */
                case UriType.Revocation.REV:
                    db = mOpenHelper.getReadableDatabase();
                    cursor = db.query(TABLE_REV, projection, selection, selectionArgs, null, null,
                            sort);
                    cursor.setNotificationUri(getContext().getContentResolver(), uri);
                    return cursor;

                default:
                    throw new IllegalArgumentException(new StringBuilder("Unsupported URI ")
                            .append(uri).append("!").toString());

            }
        } catch (RuntimeException e) {
            if (cursor != null) {
                cursor.close();
            }
            throw e;
        }
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        switch (sUriMatcher.match(uri)) {
            case UriType.Certificate.CERT_WITH_ID:
                String Id = uri.getLastPathSegment();
                selection = getCertSelectionWithId(selection);
                selectionArgs = getCertSelectionArgsWithId(selectionArgs, Id);
                /* Intentional fall through */
            case UriType.Certificate.CERT:
                SQLiteDatabase db = mOpenHelper.getWritableDatabase();
                int count = db.update(TABLE_CERT, values, selection, selectionArgs);
                if (count > 0) {
                    getContext().getContentResolver().notifyChange(uri, null);
                }
                return count;

            case UriType.Authorization.AUTH_WITH_ID:
                String iari = uri.getLastPathSegment();
                selection = getAuthSelectionWithId(selection);
                selectionArgs = getAuthSelectionArgsWithId(selectionArgs, iari);
                /* Intentional fall through */
            case UriType.Authorization.AUTH:
                db = mOpenHelper.getWritableDatabase();
                count = db.update(TABLE_AUTH, values, selection, selectionArgs);
                if (count > 0) {
                    getContext().getContentResolver().notifyChange(uri, null);
                }
                return count;

            case UriType.Revocation.REV_WITH_ID:
                String revId = uri.getLastPathSegment();
                selection = getRevocationSelectionWithId(selection);
                selectionArgs = getRevocationSelectionArgsWithId(selectionArgs, revId);
                /* Intentional fall through */
            case UriType.Revocation.REV:
                db = mOpenHelper.getWritableDatabase();
                count = db.update(TABLE_REV, values, selection, selectionArgs);
                if (count > 0) {
                    getContext().getContentResolver().notifyChange(uri, null);
                }
                return count;

            default:
                throw new IllegalArgumentException(new StringBuilder("Unsupported URI ")
                        .append(uri).append("!").toString());
        }
    }

    @Override
    public Uri insert(Uri uri, ContentValues initialValues) {
        switch (sUriMatcher.match(uri)) {
            case UriType.Certificate.CERT:
                /* Intentional fall through */
            case UriType.Certificate.CERT_WITH_ID:
                SQLiteDatabase db = mOpenHelper.getWritableDatabase();
                String id = initialValues.getAsString(CertificateData.KEY_IARI_RANGE);
                db.insert(TABLE_CERT, null, initialValues);
                Uri notificationUri = Uri.withAppendedPath(CertificateData.CONTENT_URI, id);
                getContext().getContentResolver().notifyChange(notificationUri, null);
                return notificationUri;

            case UriType.Authorization.AUTH:
                /* Intentional fall through */
            case UriType.Authorization.AUTH_WITH_ID:
                db = mOpenHelper.getWritableDatabase();
                String iari = initialValues.getAsString(AuthorizationData.KEY_IARI);
                db.insert(TABLE_AUTH, null, initialValues);
                notificationUri = Uri.withAppendedPath(AuthorizationData.CONTENT_URI, iari);
                getContext().getContentResolver().notifyChange(notificationUri, null);
                return notificationUri;

            case UriType.Revocation.REV:
                /* Intentional fall through */
            case UriType.Revocation.REV_WITH_ID:
                db = mOpenHelper.getWritableDatabase();
                String revId = initialValues.getAsString(RevocationData.KEY_SERVICE_ID);
                db.insert(TABLE_REV, null, initialValues);
                notificationUri = Uri.withAppendedPath(RevocationData.CONTENT_URI, revId);
                getContext().getContentResolver().notifyChange(notificationUri, null);
                return notificationUri;

            default:
                throw new IllegalArgumentException(new StringBuilder("Unsupported URI ")
                        .append(uri).append("!").toString());
        }
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        switch (sUriMatcher.match(uri)) {
            case UriType.Certificate.CERT_WITH_ID:
                String id = uri.getLastPathSegment();
                selection = getCertSelectionWithId(selection);
                selectionArgs = getCertSelectionArgsWithId(selectionArgs, id);
                /* Intentional fall through */
            case UriType.Certificate.CERT:
                SQLiteDatabase db = mOpenHelper.getWritableDatabase();
                int count = db.delete(TABLE_CERT, selection, selectionArgs);
                if (count > 0) {
                    getContext().getContentResolver().notifyChange(uri, null);
                }
                return count;

            case UriType.Authorization.AUTH_WITH_ID:
                String iari = uri.getLastPathSegment();
                selection = getAuthSelectionWithId(selection);
                selectionArgs = getAuthSelectionArgsWithId(selectionArgs, iari);
                /* Intentional fall through */
            case UriType.Authorization.AUTH:
                db = mOpenHelper.getWritableDatabase();
                count = db.delete(TABLE_AUTH, selection, selectionArgs);
                if (count > 0) {
                    getContext().getContentResolver().notifyChange(uri, null);
                }
                return count;

            case UriType.Revocation.REV_WITH_ID:
                String revId = uri.getLastPathSegment();
                selection = getRevocationSelectionWithId(selection);
                selectionArgs = getRevocationSelectionArgsWithId(selectionArgs, revId);
                /* Intentional fall through */
            case UriType.Revocation.REV:
                db = mOpenHelper.getWritableDatabase();
                count = db.delete(TABLE_REV, selection, selectionArgs);
                if (count > 0) {
                    getContext().getContentResolver().notifyChange(uri, null);
                }
                return count;

            default:
                throw new IllegalArgumentException(new StringBuilder("Unsupported URI ")
                        .append(uri).append("!").toString());
        }
    }
}
