package org.wso2.carbon.is.migration.service.v570.migrator;

import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.core.migrate.MigrationClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.is.migration.service.Migrator;
import org.wso2.carbon.is.migration.service.v550.bean.AuthzCodeInfo;
import org.wso2.carbon.is.migration.service.v550.util.OAuth2Util;
import org.wso2.carbon.is.migration.service.v570.dao.OAuthDAO;
import org.wso2.carbon.is.migration.util.Constant;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OAuthInfoDataMigrator extends Migrator {

    private static final Log log = LogFactory.getLog(OAuthInfoDataMigrator.class);
    private static String hashingAlgo = OAuthServerConfiguration.getInstance().getHashAlgorithm();
    private static final String ALGORITHM = "algorithm";
    private static final String HASH = "hash";

    @Override
    public void migrate() throws MigrationClientException {
        migrateAuthzCodeHash();
    }

    public void migrateAuthzCodeHash() throws MigrationClientException {

        log.info(Constant.MIGRATION_LOG + "Migration starting on Authorization code table");

        List<AuthzCodeInfo> authzCodeInfos = getAuthzCoedList();
        try {
            List<AuthzCodeInfo> updatedAuthzCodeInfoList = updateAuthzCodeHashColumnValues(authzCodeInfos, hashingAlgo);
            try (Connection connection = getDataSource().getConnection()) {
                connection.setAutoCommit(false);
                // persists modified hash values
                OAuthDAO.getInstance().updateNewAuthzCodeHash(updatedAuthzCodeInfoList, connection);
                connection.commit();
            } catch (SQLException e) {
                String error = "SQL error while updating authorization code hash";
                throw new MigrationClientException(error, e);
            }
        } catch (CryptoException e) {
            throw new MigrationClientException("Error while encrypting authorization codes.", e);
        } catch (IdentityOAuth2Exception e) {
            throw new MigrationClientException("Error while migrating authorization codes.", e);
        }
    }

    private List<AuthzCodeInfo> getAuthzCoedList() throws MigrationClientException {

        List<AuthzCodeInfo> authzCodeInfoList;
        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            authzCodeInfoList = OAuthDAO.getInstance().getAllAuthzCodes(connection);
            connection.commit();
        } catch (SQLException e) {
            String error = "SQL error while retrieving authorization code hash";
            throw new MigrationClientException(error, e);
        }

        return authzCodeInfoList;
    }

    private boolean isBase64DecodeAndIsSelfContainedCipherText(String text) throws CryptoException {

        return CryptoUtil.getDefaultCryptoUtil().base64DecodeAndIsSelfContainedCipherText(text);
    }

    private AuthzCodeInfo getAuthzCodeInfo(AuthzCodeInfo authzCodeInfo, String authzCode)
            throws IdentityOAuth2Exception {

        TokenPersistenceProcessor tokenPersistenceProcessor = new HashingPersistenceProcessor();
        String authzCodeHash = tokenPersistenceProcessor.getProcessedAuthzCode(authzCode);

        AuthzCodeInfo updatedAuthzCodeInfo = new AuthzCodeInfo(authzCode, authzCodeInfo.getCodeId());
        updatedAuthzCodeInfo.setAuthorizationCodeHash(authzCodeHash);

        return updatedAuthzCodeInfo;
    }

    private List<AuthzCodeInfo> updateAuthzCodeHashColumnValues(List<AuthzCodeInfo> authzCodeInfos, String hashAlgorithm)
            throws IdentityOAuth2Exception, CryptoException {

        List<AuthzCodeInfo> updatedAuthzCodeList = new ArrayList<>();
        if (authzCodeInfos != null) {
            boolean encryptionWithTransformationEnabled = OAuth2Util.isEncryptionWithTransformationEnabled();

            for (AuthzCodeInfo authzCodeInfo : authzCodeInfos) {
                String authzCode = authzCodeInfo.getAuthorizationCode();

                if (encryptionWithTransformationEnabled) {
                    // Code encryption is enabled.
                    if (!isBase64DecodeAndIsSelfContainedCipherText(authzCode)) {
                        // Existing codes are not encrypted with OAEP.
                        byte[] decryptedAuthzCode = CryptoUtil.getDefaultCryptoUtil()
                                                                .base64DecodeAndDecrypt(authzCode, "RSA");
                        String newEncryptedAuthzCode = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode
                                (decryptedAuthzCode);
                        TokenPersistenceProcessor tokenPersistenceProcessor = new HashingPersistenceProcessor();
                        String authzCodeHash = tokenPersistenceProcessor
                                .getProcessedAuthzCode(new String(decryptedAuthzCode, Charsets.UTF_8));
                        AuthzCodeInfo updatedAuthzCodeInfo = (new AuthzCodeInfo(newEncryptedAuthzCode,
                                                                                  authzCodeInfo.getCodeId()));
                        updatedAuthzCodeInfo.setAuthorizationCodeHash(authzCodeHash);
                        updatedAuthzCodeList.add(updatedAuthzCodeInfo);
                    } else {
                        if (StringUtils.isBlank(authzCodeInfo.getAuthorizationCodeHash())) {

                            byte[] decryptedAuthzCode = CryptoUtil.getDefaultCryptoUtil()
                                                                    .base64DecodeAndDecrypt(authzCode);

                            TokenPersistenceProcessor tokenPersistenceProcessor = new HashingPersistenceProcessor();
                            String authzCodeHash = tokenPersistenceProcessor
                                    .getProcessedAuthzCode(new String(decryptedAuthzCode, Charsets.UTF_8));

                            AuthzCodeInfo updatedAuthzCodeInfo = (new AuthzCodeInfo(authzCode, authzCodeInfo
                                    .getCodeId()));
                            updatedAuthzCodeInfo.setAuthorizationCodeHash(authzCodeHash);
                            updatedAuthzCodeList.add(updatedAuthzCodeInfo);
                        }
                    }
                } else {
                    // Code encryption is not enabled.
                    if (StringUtils.isBlank(authzCodeInfo.getAuthorizationCodeHash())) {

                        AuthzCodeInfo updatedAuthzCodeInfo = getAuthzCodeInfo(authzCodeInfo, authzCode);
                        updatedAuthzCodeList.add(updatedAuthzCodeInfo);
                    } else {
                        String oldAuthzCodeHash = authzCodeInfo.getAuthorizationCodeHash();
                        try {
                            // If hash column already is a JSON value, no need to update the record
                            new JSONObject(oldAuthzCodeHash);
                        } catch (JSONException e) {
                            // Exception is thrown because the hash value is not a json
                            JSONObject authzCodeHashObject = new JSONObject();
                            authzCodeHashObject.put(ALGORITHM, hashAlgorithm);
                            authzCodeHashObject.put(HASH, oldAuthzCodeHash);
                            AuthzCodeInfo updatedAuthzCodeInfo = (new AuthzCodeInfo(authzCode, authzCodeInfo
                                    .getCodeId()));
                            updatedAuthzCodeInfo.setAuthorizationCodeHash(authzCodeHashObject.toString());
                            updatedAuthzCodeList.add(updatedAuthzCodeInfo);
                        }
                    }
                }
            }
        }
        return updatedAuthzCodeList;
    }
}
