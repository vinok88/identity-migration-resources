/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.is.migration.service.v550.migrator;

import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.core.migrate.MigrationClientException;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.is.migration.service.Migrator;
import org.wso2.carbon.is.migration.service.v550.bean.AuthzCodeInfo;
import org.wso2.carbon.is.migration.service.v550.bean.ClientSecretInfo;
import org.wso2.carbon.is.migration.service.v550.bean.OauthTokenInfo;
import org.wso2.carbon.is.migration.service.v550.dao.AuthzCodeDAO;
import org.wso2.carbon.is.migration.service.v550.dao.OAuthDAO;
import org.wso2.carbon.is.migration.service.v550.util.OAuth2Util;
import org.wso2.carbon.is.migration.util.Constant;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OAuthInfoDataMigrator extends Migrator {

    private static final Log log = LogFactory
            .getLog(OAuthInfoDataMigrator.class);
    boolean isAuthzCodeHashColumnAvailable = false;
    boolean isClientSecretHashColumnsAvailable = false;

    @Override
    public void migrate() throws MigrationClientException {
        try {
            addAuthorizeCodeHashColumns();
            deleteClientSecretHashColumn();
            migrateAuthorizationCodes();
            migrateClientSecrets();
        } catch (SQLException e) {
            throw new MigrationClientException("Error while adding hash columns", e);
        }
    }

    public void addAuthorizeCodeHashColumns() throws MigrationClientException, SQLException {

        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            isAuthzCodeHashColumnAvailable = AuthzCodeDAO.getInstance().isAuthzCodeHashColumnAvailable(connection);
            connection.commit();
        }
        if (!isAuthzCodeHashColumnAvailable) {
            try (Connection connection = getDataSource().getConnection()) {
                connection.setAutoCommit(false);
                AuthzCodeDAO.getInstance().addAuthzCodeHashColumns(connection);
                connection.commit();
            }
        }
    }

    public void deleteClientSecretHashColumn() throws MigrationClientException, SQLException {

        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            isClientSecretHashColumnsAvailable = OAuthDAO.getInstance().isConsumerSecretHashColumnAvailable(connection);
            connection.commit();
        }
        if (isClientSecretHashColumnsAvailable) {
            try (Connection connection = getDataSource().getConnection()) {
                connection.setAutoCommit(false);
                OAuthDAO.getInstance().deleteConsumerSecretHashColumn(connection);
                connection.commit();
            }
        }
    }

    private boolean isBase64DecodeAndIsSelfContainedCipherText(String text) throws CryptoException {

        return CryptoUtil.getDefaultCryptoUtil().base64DecodeAndIsSelfContainedCipherText(text);
    }

    private List<OauthTokenInfo> generateTokenHashValues(List<OauthTokenInfo> oauthTokenList)
            throws IdentityOAuth2Exception {

        List<OauthTokenInfo> updatedOauthTokenList = new ArrayList<>();

        for (OauthTokenInfo oauthTokenInfo : oauthTokenList) {
            if (StringUtils.isBlank(oauthTokenInfo.getAccessTokenHash())) {
                String accessToken = oauthTokenInfo.getAccessToken();
                String refreshToken = oauthTokenInfo.getRefreshToken();
                TokenPersistenceProcessor tokenPersistenceProcessor = new HashingPersistenceProcessor();
                String accessTokenHash = tokenPersistenceProcessor.getProcessedAccessTokenIdentifier(accessToken);
                String refreshTokenHash = null;
                if (refreshToken != null) {
                    refreshTokenHash = tokenPersistenceProcessor.getProcessedRefreshToken(refreshToken);
                }
                OauthTokenInfo updatedOauthTokenInfo = (new OauthTokenInfo(accessToken, refreshToken,
                        oauthTokenInfo.getTokenId()));
                updatedOauthTokenInfo.setAccessTokenHash(accessTokenHash);
                updatedOauthTokenInfo.setRefreshTokenHash(refreshTokenHash);
                updatedOauthTokenList.add(updatedOauthTokenInfo);
            }
        }
        return updatedOauthTokenList;
    }

    /**
     * Method to migrate old encrypted authorization codes/ plain text authorization codes.
     *
     * @throws MigrationClientException
     * @throws SQLException
     */
    public void migrateAuthorizationCodes() throws MigrationClientException, SQLException {

        log.info(Constant.MIGRATION_LOG + "Migration starting on OAuth2 authorization code table.");
        List<AuthzCodeInfo> authzCodeInfoList;
        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            authzCodeInfoList = AuthzCodeDAO.getInstance().getAllAuthzCodesWithHashes(connection);
        }
        try {
            //migrating RSA encrypted authz codes to OAEP encryption
            if (OAuth2Util.isEncryptionWithTransformationEnabled()) {
                migrateOldEncryptedAuthzCodes(authzCodeInfoList);
            }
            //migrating plaintext authz codes with hashed authz codes.
            if (!OAuth2Util.isTokenEncryptionEnabled()) {
                migratePlainTextAuthzCodes(authzCodeInfoList);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new MigrationClientException(
                    "Error while checking configurations for encryption with " + "transformation is enabled. ", e);
        } catch (SQLException e) {
            throw new MigrationClientException("Error while getting datasource connection. ", e);
        }
    }

    /**
     * This method will migrate authorization codes encrypted in RSA to OAEP.
     *
     * @param authzCodeInfoList list of authz codes
     * @throws MigrationClientException
     * @throws SQLException
     */
    public void migrateOldEncryptedAuthzCodes(List<AuthzCodeInfo> authzCodeInfoList)
            throws MigrationClientException, SQLException {

        log.info(Constant.MIGRATION_LOG
                + "Migration starting on OAuth2 authorization table with encrypted authorization codes.");
        try {
            List<AuthzCodeInfo> updatedAuthzCodeInfoList = transformAuthzCodeFromOldToNewEncryption(authzCodeInfoList);
            try (Connection connection = getDataSource().getConnection()) {
                connection.setAutoCommit(false);
                AuthzCodeDAO.getInstance().updateNewEncryptedAuthzCodes(updatedAuthzCodeInfoList, connection);
            }
        } catch (CryptoException e) {
            throw new MigrationClientException("Error while encrypting in new encryption algorithm.", e);
        } catch (IdentityOAuth2Exception e) {
            throw new MigrationClientException("Error while migrating old encrypted authz codes.", e);
        }

    }

    /**
     * This method will generate hash values of authorization codes and update the authorization code table with those values
     *
     * @param authzCodeInfoList
     * @throws MigrationClientException
     * @throws SQLException
     */
    public void migratePlainTextAuthzCodes(List<AuthzCodeInfo> authzCodeInfoList)
            throws MigrationClientException, SQLException {

        log.info(Constant.MIGRATION_LOG
                + "Migration starting on OAuth2 authorization code table with plain text codes.");
        try {
            List<AuthzCodeInfo> updatedAuthzCodeInfoList = generateAuthzCodeHashValues(authzCodeInfoList);
            try (Connection connection = getDataSource().getConnection()) {
                connection.setAutoCommit(false);
                AuthzCodeDAO.getInstance().updatePlainTextAuthzCodes(updatedAuthzCodeInfoList, connection);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new MigrationClientException("Error while migration plain text authorization codes.", e);
        }
    }

    private List<AuthzCodeInfo> transformAuthzCodeFromOldToNewEncryption(List<AuthzCodeInfo> authzCodeInfoList)
            throws CryptoException, IdentityOAuth2Exception {

        List<AuthzCodeInfo> updatedAuthzCodeInfoList = new ArrayList<>();
        for (AuthzCodeInfo authzCodeInfo : authzCodeInfoList) {
            if (!isBase64DecodeAndIsSelfContainedCipherText(authzCodeInfo.getAuthorizationCode())) {
                byte[] decryptedAuthzCode = CryptoUtil.getDefaultCryptoUtil()
                        .base64DecodeAndDecrypt(authzCodeInfo.getAuthorizationCode(), "RSA");
                String newEncryptedAuthzCode = CryptoUtil.getDefaultCryptoUtil()
                        .encryptAndBase64Encode(decryptedAuthzCode);
                TokenPersistenceProcessor tokenPersistenceProcessor = new HashingPersistenceProcessor();
                String authzCodeHash;
                authzCodeHash = tokenPersistenceProcessor
                        .getProcessedAuthzCode(new String(decryptedAuthzCode, Charsets.UTF_8));

                AuthzCodeInfo updatedAuthzCodeInfo = (new AuthzCodeInfo(newEncryptedAuthzCode,
                        authzCodeInfo.getCodeId()));
                updatedAuthzCodeInfo.setAuthorizationCodeHash(authzCodeHash);
                updatedAuthzCodeInfoList.add(updatedAuthzCodeInfo);
            } else if (isBase64DecodeAndIsSelfContainedCipherText(authzCodeInfo.getAuthorizationCode()) &&
                    StringUtils.isBlank(authzCodeInfo.getAuthorizationCodeHash())) {
                byte[] decryptedAuthzCode = CryptoUtil.getDefaultCryptoUtil()
                        .base64DecodeAndDecrypt(authzCodeInfo.getAuthorizationCode());
                TokenPersistenceProcessor tokenPersistenceProcessor = new HashingPersistenceProcessor();
                String authzCodeHash;
                authzCodeHash = tokenPersistenceProcessor
                        .getProcessedAuthzCode(new String(decryptedAuthzCode, Charsets.UTF_8));

                AuthzCodeInfo updatedAuthzCodeInfo = (new AuthzCodeInfo(authzCodeInfo.getAuthorizationCode(),
                        authzCodeInfo.getCodeId()));
                updatedAuthzCodeInfo.setAuthorizationCodeHash(authzCodeHash);
                updatedAuthzCodeInfoList.add(updatedAuthzCodeInfo);
            }
        }
        return updatedAuthzCodeInfoList;
    }

    private List<AuthzCodeInfo> generateAuthzCodeHashValues(List<AuthzCodeInfo> authzCodeInfoList)
            throws IdentityOAuth2Exception {

        List<AuthzCodeInfo> updatedAuthzCodeInfoList = new ArrayList<>();
        for (AuthzCodeInfo authzCodeInfo : authzCodeInfoList) {

            if (StringUtils.isBlank(authzCodeInfo.getAuthorizationCodeHash())) {
                String authorizationCode = authzCodeInfo.getAuthorizationCode();
                TokenPersistenceProcessor tokenPersistenceProcessor = new HashingPersistenceProcessor();
                String authzCodeHash = tokenPersistenceProcessor.getProcessedAuthzCode(authorizationCode);
                AuthzCodeInfo updatedAuthzCodeInfo = new AuthzCodeInfo(authorizationCode, authzCodeInfo.getCodeId());
                updatedAuthzCodeInfo.setAuthorizationCodeHash(authzCodeHash);
                updatedAuthzCodeInfoList.add(updatedAuthzCodeInfo);
            }
        }
        return updatedAuthzCodeInfoList;
    }

    /**
     * Method to migrate old encrypted client secrets to new encrypted client secrets
     *
     * @throws MigrationClientException
     */
    public void migrateClientSecrets() throws MigrationClientException {

        log.info(Constant.MIGRATION_LOG + "Migration starting on OAuth2 consumer apps table.");
        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            if (OAuth2Util.isEncryptionWithTransformationEnabled()) {
                List<ClientSecretInfo> clientSecretInfoList;
                clientSecretInfoList = OAuthDAO.getInstance().getAllClientSecrets(connection);
                List<ClientSecretInfo> updatedClientSecretInfoList = null;
                updatedClientSecretInfoList = transformClientSecretFromOldToNewEncryption(clientSecretInfoList);
                OAuthDAO.getInstance().updateNewClientSecrets(updatedClientSecretInfoList, connection);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new MigrationClientException("Error while checking encryption with transformation is enabled. ", e);
        } catch (SQLException e) {
            throw new MigrationClientException("Error while retrieving and updating client secrets. ", e);
        }
    }

    private List<ClientSecretInfo> transformClientSecretFromOldToNewEncryption(
            List<ClientSecretInfo> clientSecretInfoList) throws MigrationClientException {

        List<ClientSecretInfo> updatedClientSecretList = new ArrayList<>();
        for (ClientSecretInfo clientSecretInfo : clientSecretInfoList) {
            try {
                if (!CryptoUtil.getDefaultCryptoUtil()
                        .base64DecodeAndIsSelfContainedCipherText(clientSecretInfo.getClientSecret())) {
                    byte[] decryptedClientSecret = CryptoUtil.getDefaultCryptoUtil()
                            .base64DecodeAndDecrypt(clientSecretInfo.getClientSecret(), "RSA");
                    String newEncryptedClientSecret = CryptoUtil.getDefaultCryptoUtil()
                            .encryptAndBase64Encode(decryptedClientSecret);
                    ClientSecretInfo updatedClientSecretInfo = (new ClientSecretInfo(newEncryptedClientSecret,
                            clientSecretInfo.getId()));
                    updatedClientSecretList.add(updatedClientSecretInfo);
                }
            } catch (CryptoException e) {
                if (isContinueOnError()) {
                    log.error("Error when migrating the secret for client with app ID: " +
                            clientSecretInfo.getId(), e);
                } else {
                    throw new MigrationClientException("Error when migrating the secret for client with app ID: " +
                            clientSecretInfo.getId(), e);
                }
            }
        }
        return updatedClientSecretList;
    }

}
