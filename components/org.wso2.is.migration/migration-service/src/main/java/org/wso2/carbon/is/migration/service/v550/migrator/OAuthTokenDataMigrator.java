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
import org.wso2.carbon.is.migration.service.v550.bean.OauthTokenInfo;
import org.wso2.carbon.is.migration.service.v550.dao.TokenDAO;
import org.wso2.carbon.is.migration.service.v550.util.OAuth2Util;
import org.wso2.carbon.is.migration.util.Constant;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OAuthTokenDataMigrator extends Migrator {

    private static final Log log = LogFactory.getLog(org.wso2.carbon.is.migration.service.v550.migrator.OAuthTokenDataMigrator.class);
    boolean isTokenHashColumnsAvailable = false;

    @Override
    public void migrate() throws MigrationClientException {
        try {
            addTokenHashColumns();
            migrateTokens();
        } catch (Exception e) {
            log.error("SQl Exception when execute  token migration.",e);
            if (!isContinueOnError()) {
                throw new MigrationClientException(e.getMessage(), e);
            }
        }
    }

    private void addTokenHashColumns() throws MigrationClientException, SQLException {

        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            isTokenHashColumnsAvailable = TokenDAO.getInstance().isTokenHashColumnsAvailable(connection);
            connection.commit();
        }
        if (!isTokenHashColumnsAvailable) {
            try (Connection connection = getDataSource().getConnection()) {
                connection.setAutoCommit(false);
                TokenDAO.getInstance().addAccessTokenHashColumn(connection);
                TokenDAO.getInstance().addRefreshTokenHashColumn(connection);
                connection.commit();
            }
        }
    }

    /**
     * Method to migrate encrypted tokens/plain text tokens.
     *
     * @throws MigrationClientException
     * @throws SQLException
     */
    private void migrateTokens() throws MigrationClientException, SQLException {

        log.info(Constant.MIGRATION_LOG + "Migration starting on OAuth2 access token table.");
        List<OauthTokenInfo> oauthTokenList;
        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            oauthTokenList = TokenDAO.getInstance().getAllAccessTokensWithHash(connection);
        }
        try {
            //migrating RSA encrypted tokens to OAEP encryption
            if (OAuth2Util.isEncryptionWithTransformationEnabled()) {
                migrateOldEncryptedTokens(oauthTokenList);
            }
            //migrating plaintext tokens with hashed tokens.
            if (!OAuth2Util.isTokenEncryptionEnabled()) {
                migratePlainTextTokens(oauthTokenList);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new MigrationClientException(e.getMessage(), e);
        }
    }

    private void migrateOldEncryptedTokens(List<OauthTokenInfo> oauthTokenList)
            throws MigrationClientException, SQLException {

        log.info(Constant.MIGRATION_LOG + "Migration starting on OAuth2 access token table with encrypted tokens.");
        List<OauthTokenInfo> updatedOauthTokenList = transformFromOldToNewEncryption(oauthTokenList);

        try (Connection connection = getDataSource().getConnection()) {
            connection.setAutoCommit(false);
            TokenDAO.getInstance().updateNewEncryptedTokens(updatedOauthTokenList, connection);
        }

    }

    /**
     * Method to migrate plain text tokens. This will add hashed tokens to acess token and refresh token hash columns.
     *
     * @param oauthTokenList list of tokens to be migrated
     * @throws IdentityOAuth2Exception
     * @throws MigrationClientException
     * @throws SQLException
     */
    private void migratePlainTextTokens(List<OauthTokenInfo> oauthTokenList)
            throws IdentityOAuth2Exception, MigrationClientException, SQLException {

        log.info(Constant.MIGRATION_LOG + "Migration starting on OAuth2 access token table with plain text tokens.");
        try {
            List<OauthTokenInfo> updatedOauthTokenList = generateTokenHashValues(oauthTokenList);
            try (Connection connection = getDataSource().getConnection()) {
                connection.setAutoCommit(false);
                TokenDAO.getInstance().updatePlainTextTokens(updatedOauthTokenList, connection);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuth2Exception("Error while migration plain text tokens", e);
        }
    }

    private List<OauthTokenInfo> transformFromOldToNewEncryption(List<OauthTokenInfo> oauthTokenList)
            throws MigrationClientException {

        List<OauthTokenInfo> updatedOauthTokenList = new ArrayList<>();
        TokenPersistenceProcessor hashingPersistenceProcessor = new HashingPersistenceProcessor();

        for (OauthTokenInfo oauthTokenInfo : oauthTokenList) {
            String accessToken = oauthTokenInfo.getAccessToken();
            String refreshToken = oauthTokenInfo.getRefreshToken();
            OauthTokenInfo updatedTokenInfo = null;
            if (accessToken != null) {
                try {
                    boolean accessTokenSelfContained = isBase64DecodeAndIsSelfContainedCipherText(accessToken);
                    if (!accessTokenSelfContained) {
                        byte[] decryptedAccessToken = CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(accessToken,
                                "RSA");
                        String newEncryptedAccessToken =
                                CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(decryptedAccessToken);
                        String accessTokenHash =
                                hashingPersistenceProcessor.getProcessedAccessTokenIdentifier(
                                        new String(decryptedAccessToken, Charsets.UTF_8));
                        updatedTokenInfo = new OauthTokenInfo(oauthTokenInfo);
                        updatedTokenInfo.setAccessToken(newEncryptedAccessToken);
                        updatedTokenInfo.setAccessTokenHash(accessTokenHash);
                    }

                    if (accessTokenSelfContained && StringUtils.isBlank(oauthTokenInfo.getAccessTokenHash())) {
                        byte[] decryptedAccessToken = CryptoUtil.getDefaultCryptoUtil()
                                .base64DecodeAndDecrypt(accessToken);
                        String accessTokenHash =
                                hashingPersistenceProcessor.getProcessedAccessTokenIdentifier(
                                        new String(decryptedAccessToken, Charsets.UTF_8));
                        updatedTokenInfo = new OauthTokenInfo(oauthTokenInfo);
                        updatedTokenInfo.setAccessTokenHash(accessTokenHash);
                    }
                } catch (CryptoException | IdentityOAuth2Exception e) {
                    if (isContinueOnError()) {
                        log.error("Error when migrating the access token with token id: " +
                                oauthTokenInfo.getTokenId(), e);
                    } else {
                        throw new MigrationClientException("Error when migrating the access token with token id: " +
                                oauthTokenInfo.getTokenId(), e);
                    }
                }
            } else {
                log.debug("Access token is null for token id: " + oauthTokenInfo.getTokenId());
            }

            if (refreshToken != null) {
                try {
                    boolean refreshTokenSelfContained = isBase64DecodeAndIsSelfContainedCipherText(refreshToken);
                    if (!refreshTokenSelfContained) {
                        byte[] decryptedRefreshToken = CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(refreshToken,
                                "RSA");
                        String newEncryptedRefreshToken =
                                CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(decryptedRefreshToken);
                        String refreshTokenHash =
                                hashingPersistenceProcessor.getProcessedAccessTokenIdentifier(new String(decryptedRefreshToken
                                        , Charsets.UTF_8));
                        if (updatedTokenInfo == null) {
                            updatedTokenInfo = new OauthTokenInfo(oauthTokenInfo);
                        }
                        updatedTokenInfo.setRefreshToken(newEncryptedRefreshToken);
                        updatedTokenInfo.setRefreshTokenHash(refreshTokenHash);
                    }

                    if (refreshTokenSelfContained && StringUtils.isBlank(oauthTokenInfo.getRefreshTokenHash())) {
                        byte[] decryptedRefreshToken = CryptoUtil.getDefaultCryptoUtil()
                                .base64DecodeAndDecrypt(refreshToken);
                        String refreshTokenHash =
                                hashingPersistenceProcessor.getProcessedAccessTokenIdentifier(
                                        new String(decryptedRefreshToken, Charsets.UTF_8));
                        if (updatedTokenInfo == null) {
                            updatedTokenInfo = new OauthTokenInfo(oauthTokenInfo);
                            updatedTokenInfo.setRefreshTokenHash(refreshTokenHash);
                        }
                    }
                } catch (CryptoException | IdentityOAuth2Exception e) {
                    if (isContinueOnError()) {
                        log.error("Error when migrating the refresh token with token id: " +
                                oauthTokenInfo.getTokenId(), e);
                    } else {
                        throw new MigrationClientException("Error when migrating the refresh token with token id: " +
                                oauthTokenInfo.getTokenId(), e);
                    }
                }
            } else {
                log.debug("Refresh token is null for token id: " + oauthTokenInfo.getTokenId());
            }

            if (updatedTokenInfo != null) {
                updatedOauthTokenList.add(updatedTokenInfo);
            }
        }
        return updatedOauthTokenList;
    }

    private boolean isBase64DecodeAndIsSelfContainedCipherText(String text) throws CryptoException {

        return CryptoUtil.getDefaultCryptoUtil().base64DecodeAndIsSelfContainedCipherText(text);
    }

    private List<OauthTokenInfo> generateTokenHashValues(List<OauthTokenInfo> oauthTokenList) throws IdentityOAuth2Exception {

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
}
