ALTER TABLE IDN_OAUTH_CONSUMER_APPS ADD USER_ACCESS_TOKEN_EXPIRE_TIME BIGINT DEFAULT 3600000 WITH VALUES;
ALTER TABLE IDN_OAUTH_CONSUMER_APPS ADD APP_ACCESS_TOKEN_EXPIRE_TIME BIGINT DEFAULT 3600000 WITH VALUES;
ALTER TABLE IDN_OAUTH_CONSUMER_APPS ADD REFRESH_TOKEN_EXPIRE_TIME BIGINT DEFAULT 84600000 WITH VALUES;

IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[DBO].[IDN_OAUTH2_SCOPE_BINDING]') AND TYPE IN (N'U'))
CREATE TABLE IDN_OAUTH2_SCOPE_BINDING (
  SCOPE_ID INTEGER NOT NULL,
  SCOPE_BINDING VARCHAR(255),
  FOREIGN KEY (SCOPE_ID) REFERENCES IDN_OAUTH2_SCOPE(SCOPE_ID) ON DELETE CASCADE
);

ALTER TABLE IDN_IDENTITY_USER_DATA ALTER COLUMN DATA_VALUE VARCHAR(2048);
