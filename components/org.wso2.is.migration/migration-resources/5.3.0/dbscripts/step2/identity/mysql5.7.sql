DROP PROCEDURE IF EXISTS drop_index_if_exists;
CREATE PROCEDURE drop_index_if_exists() BEGIN IF((SELECT COUNT(*) AS index_exists FROM information_schema.statistics WHERE TABLE_SCHEMA = DATABASE() and table_name = 'IDN_OAUTH2_ACCESS_TOKEN' AND index_name = 'IDX_IOAT_AT') > 0) THEN SET @s = CONCAT('DROP INDEX ' , 'IDX_IOAT_AT' , ' ON ' , 'IDN_OAUTH2_ACCESS_TOKEN'); PREPARE stmt FROM @s; EXECUTE stmt; END IF; END;
CALL drop_index_if_exists();


