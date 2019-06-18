/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.is.migration.service.v530.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.migrate.MigrationClientException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.is.migration.service.v530.SQLConstants;
import org.wso2.carbon.utils.DBUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Data Access layer for IDP Metadata table
 */
public class IdpMetaDataDAO {

    private static Log log = LogFactory.getLog(IdpMetaDataDAO.class);

    private static IdpMetaDataDAO idpMetaDataDAO = new IdpMetaDataDAO();

    private IdpMetaDataDAO() {

    }

    public static IdpMetaDataDAO getInstance() {

        return idpMetaDataDAO;
    }


    public int getResidentIdpId(int tenantId) throws MigrationClientException {

        // we use the IDP table to find the resident idp id.
        String sql = "SELECT ID FROM IDP WHERE NAME='LOCAL' AND TENANT_ID=?";

        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        int residentIdpId = -9999;
        try {
            String dbProductName = connection.getMetaData().getDatabaseProductName();
            prepStmt = connection.prepareStatement(sql, new String[]{
                    DBUtils.getConvertedAutoGeneratedColumnName(dbProductName, SQLConstants.ID_COLUMN)});

            prepStmt.setInt(1, tenantId);
            rs = prepStmt.executeQuery();

            if (rs.next()) {
                residentIdpId = rs.getInt("ID");
            }
        } catch (SQLException e) {
            throw new MigrationClientException("Error while retrieving resident idp id of tenant : " + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, prepStmt);
        }

        return residentIdpId;
    }


    public List<String> getAvailableConfigNames(int tenantId, int residentIdpId) throws MigrationClientException {

        String sql = "SELECT NAME FROM IDP_METADATA WHERE TENANT_ID=? AND IDP_ID=?";
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        List<String> residentIdpPropertyNames = new ArrayList<>();
        try {
            String dbProductName = connection.getMetaData().getDatabaseProductName();
            prepStmt = connection.prepareStatement(sql, new String[]{
                    DBUtils.getConvertedAutoGeneratedColumnName(dbProductName, SQLConstants.ID_COLUMN)});

            prepStmt.setInt(1, tenantId);
            prepStmt.setInt(2, residentIdpId);
            rs = prepStmt.executeQuery();

            while (rs.next()) {
                residentIdpPropertyNames.add(rs.getString("NAME"));
            }
        } catch (SQLException e) {
            throw new MigrationClientException("Error while retrieving resident idp properties of tenant : " +
                                               tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, prepStmt);
        }

        return residentIdpPropertyNames;
    }


    public void addIdpMetaData(List<IdpMetaData> idpMetaDataDAOs) throws MigrationClientException {

        String sql = "INSERT INTO IDP_METADATA(IDP_ID, NAME, VALUE, DISPLAY_NAME, TENANT_ID) values(?,?,?,?,?)";

        PreparedStatement prepStmt = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            String dbProductName = connection.getMetaData().getDatabaseProductName();
            prepStmt = connection.prepareStatement(sql, new String[]{ DBUtils.getConvertedAutoGeneratedColumnName
                    (dbProductName, SQLConstants.ID_COLUMN)});

            for (IdpMetaData idpMetaData : idpMetaDataDAOs) {
                prepStmt.setInt(1, idpMetaData.getIdpId());
                prepStmt.setString(2, idpMetaData.getName());
                prepStmt.setString(3, idpMetaData.getValue());
                prepStmt.setString(4, idpMetaData.getDisplayName());
                prepStmt.setInt(5, idpMetaData.getTenantId());
                prepStmt.executeUpdate();
            }
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new MigrationClientException("Error while inserting default resident idp property values.", e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    public static class IdpMetaData {

        private int idpId;
        private String name;
        private String value;
        private String displayName;
        private int tenantId;

        public IdpMetaData(int idpId, String name, String value, String displayName, int tenantId) {

            this.idpId = idpId;
            this.name = name;
            this.value = value;
            this.displayName = displayName;
            this.tenantId = tenantId;
        }

        public int getIdpId() {

            return idpId;
        }

        public String getName() {

            return name;
        }

        public String getValue() {

            return value;
        }

        public String getDisplayName() {

            return displayName;
        }

        public int getTenantId() {

            return tenantId;
        }
    }
}
