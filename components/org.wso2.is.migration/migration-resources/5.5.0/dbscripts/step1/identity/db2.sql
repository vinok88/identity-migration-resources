BEGIN
  DECLARE CONTINUE HANDLER FOR SQLSTATE '42704'
  BEGIN END;
  EXECUTE IMMEDIATE 'DROP INDEX IDX_AT';
END
/

BEGIN
  DECLARE CONTINUE HANDLER FOR SQLSTATE '42704'
  BEGIN END;
  EXECUTE IMMEDIATE 'DROP INDEX IDX_AUTHORIZATION_CODE';
END
/
--ALTER TABLE IDN_OAUTH2_ACCESS_TOKEN ALTER COLUMN REFRESH_TOKEN SET DATA TYPE VARCHAR(2048)
--/
--ALTER TABLE IDN_OAUTH2_ACCESS_TOKEN ALTER COLUMN ACCESS_TOKEN SET DATA TYPE VARCHAR(2048)
--/
ALTER TABLE IDN_OAUTH2_AUTHORIZATION_CODE ALTER COLUMN AUTHORIZATION_CODE SET DATA TYPE VARCHAR(2048)
/
ALTER TABLE IDN_OAUTH_CONSUMER_APPS ALTER COLUMN CONSUMER_SECRET SET DATA TYPE VARCHAR(2048)
/

CREATE TABLE IDN_OAUTH2_SCOPE_VALIDATORS (
	APP_ID INTEGER NOT NULL,
	SCOPE_VALIDATOR VARCHAR (128) NOT NULL,
	PRIMARY KEY (APP_ID, SCOPE_VALIDATOR),
	FOREIGN KEY (APP_ID) REFERENCES IDN_OAUTH_CONSUMER_APPS(ID) ON DELETE CASCADE
)
/
CREATE TABLE SP_AUTH_SCRIPT (
  ID         INTEGER      NOT NULL,
  TENANT_ID  INTEGER      NOT NULL,
  APP_ID     INTEGER      NOT NULL,
  TYPE       VARCHAR(255) NOT NULL,
  CONTENT    BLOB    DEFAULT NULL,
  IS_ENABLED CHAR(1) DEFAULT '0',
  PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_AUTH_SCRIPT_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE TRIGGER SP_AUTH_SCRIPT_TRIG NO CASCADE
            BEFORE INSERT
            ON SP_AUTH_SCRIPT
            REFERENCING NEW AS NEW
            FOR EACH ROW MODE DB2SQL
                BEGIN ATOMIC
                    SET (NEW.ID) = (NEXTVAL FOR SP_AUTH_SCRIPT_SEQ);
                END
/
CREATE TABLE IDN_OIDC_JTI (
  JWT_ID VARCHAR(255) NOT NULL,
  EXP_TIME TIMESTAMP NOT NULL,
  TIME_CREATED TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (JWT_ID))
/


CREATE TABLE IDN_OIDC_PROPERTY (
  ID INTEGER NOT NULL,
  TENANT_ID  INTEGER,
  CONSUMER_KEY  VARCHAR(255) ,
  PROPERTY_KEY  VARCHAR(255) NOT NULL,
  PROPERTY_VALUE  VARCHAR(2047) ,
  PRIMARY KEY (ID),
  FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE)
/
CREATE SEQUENCE IDN_OIDC_PROPERTY_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE TRIGGER IDN_OIDC_PROPERTY_TRIG NO CASCADE
            BEFORE INSERT
            ON IDN_OIDC_PROPERTY
            REFERENCING NEW AS NEW
            FOR EACH ROW MODE DB2SQL
                BEGIN ATOMIC
                    SET (NEW.ID) = (NEXTVAL FOR IDN_OIDC_PROPERTY_SEQ);
                END
/

CREATE TABLE IDN_OIDC_REQ_OBJECT_REFERENCE (
  ID INTEGER NOT NULL,
  CONSUMER_KEY_ID INTEGER ,
  CODE_ID VARCHAR(255) ,
  TOKEN_ID VARCHAR(255) ,
  SESSION_DATA_KEY VARCHAR(255),
  PRIMARY KEY (ID),
  FOREIGN KEY (CONSUMER_KEY_ID) REFERENCES IDN_OAUTH_CONSUMER_APPS(ID) ON DELETE CASCADE,
  FOREIGN KEY (TOKEN_ID) REFERENCES IDN_OAUTH2_ACCESS_TOKEN(TOKEN_ID) ON DELETE CASCADE,
  FOREIGN KEY (CODE_ID) REFERENCES IDN_OAUTH2_AUTHORIZATION_CODE(CODE_ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDN_OIDC_REQUEST_OBJECT_REF_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE TRIGGER IDN_OIDC_REQUEST_OBJECT_REF_TRIG NO CASCADE
            BEFORE INSERT
            ON IDN_OIDC_REQ_OBJECT_REFERENCE
            REFERENCING NEW AS NEW
            FOR EACH ROW MODE DB2SQL
               BEGIN ATOMIC
                   SET (NEW.ID) = (NEXTVAL FOR IDN_OIDC_REQUEST_OBJECT_REF_SEQ);
               END
/

CREATE TABLE IDN_OIDC_REQ_OBJECT_CLAIMS (
  ID INTEGER NOT NULL,
  REQ_OBJECT_ID INTEGER ,
  CLAIM_ATTRIBUTE VARCHAR(255),
  ESSENTIAL CHAR(1) NOT NULL DEFAULT '0',
  VALUE VARCHAR(255),
  IS_USERINFO CHAR(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (ID),
  FOREIGN KEY (REQ_OBJECT_ID) REFERENCES IDN_OIDC_REQ_OBJECT_REFERENCE(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDN_OIDC_REQ_OBJECT_CLAIMS_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE TRIGGER IDN_OIDC_REQ_OBJECT_CLAIMS_TRIG NO CASCADE
            BEFORE INSERT
            ON IDN_OIDC_REQ_OBJECT_CLAIMS
            REFERENCING NEW AS NEW
            FOR EACH ROW MODE DB2SQL
               BEGIN ATOMIC
                   SET (NEW.ID) = (NEXTVAL FOR IDN_OIDC_REQ_OBJECT_CLAIMS_SEQ);
               END
/

CREATE TABLE IDN_OIDC_REQ_OBJ_CLAIM_VALUES (
  ID INTEGER NOT NULL,
  REQ_OBJECT_CLAIMS_ID INTEGER,
  CLAIM_VALUES VARCHAR(255),
  PRIMARY KEY (ID),
  FOREIGN KEY (REQ_OBJECT_CLAIMS_ID) REFERENCES IDN_OIDC_REQ_OBJECT_CLAIMS(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDN_OIDC_REQ_OBJECT_CLAIM_VALUES_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE TRIGGER IDN_OIDC_REQ_OBJECT_CLAIM_VALUES_TRIG
            BEFORE INSERT
            ON IDN_OIDC_REQ_OBJ_CLAIM_VALUES
            REFERENCING NEW AS NEW
            FOR EACH ROW MODE DB2SQL
               BEGIN ATOMIC
                   SET (NEW.ID) = (NEXTVAL FOR IDN_OIDC_REQ_OBJECT_CLAIM_VALUES_SEQ);
               END
/

CREATE TABLE IDN_CERTIFICATE (
            ID INTEGER NOT NULL,
            NAME VARCHAR(100) NOT NULL,
            CERTIFICATE_IN_PEM BLOB,
            TENANT_ID INTEGER NOT NULL,
            CONSTRAINT CERTIFICATE_UNIQUE_KEY UNIQUE (NAME, TENANT_ID),
            PRIMARY KEY (ID))
/
CREATE SEQUENCE IDN_CERTIFICATE_SEQUENCE START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE TRIGGER IDN_CERTIFICATE_TRIGGER NO CASCADE BEFORE INSERT ON IDN_CERTIFICATE
REFERENCING NEW AS NEW FOR EACH ROW MODE DB2SQL
  BEGIN ATOMIC
    SET (NEW.ID)
    = (NEXTVAL FOR IDN_CERTIFICATE_SEQUENCE);
  END
/
