CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `login` varchar(255) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `salt` varchar(255) NOT NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `login_log` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `created_at` datetime NOT NULL,
  `user_id` int,
  `login` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `succeeded` tinyint NOT NULL,

  KEY (user_id),
  KEY (ip)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `last_login_success_user_id` (
  `user_id` int NOT NULL UNIQUE,
  `login_log_id` bigint NOT NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `last_login_success_ip` (
  `ip` varchar(255) NOT NULL UNIQUE,
  `login_log_id` bigint NOT NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `last_login_failure_count_user_id` (
  `user_id` int NOT NULL UNIQUE,
  `count` int
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `last_login_failure_count_ip` (
  `ip` varchar(255) NOT NULL UNIQUE,
  `count` int
) DEFAULT CHARSET=utf8;

DELIMITER //
CREATE TRIGGER login_log_insert AFTER INSERT ON login_log
FOR EACH ROW
BEGIN
    IF NEW.succeeded = 1 THEN
        INSERT INTO last_login_success_user_id SET user_id=NEW.user_id, login_log_id=NEW.id ON DUPLICATE KEY UPDATE login_log_id=NEW.id;
        INSERT INTO last_login_success_ip SET ip=NEW.ip, login_log_id=NEW.id                ON DUPLICATE KEY UPDATE login_log_id=NEW.id;
        DELETE FROM last_login_failure_count_user_id WHERE user_id=NEW.user_id;
        DELETE FROM last_login_failure_count_ip      WHERE ip=NEW.ip;
    ELSE
        INSERT INTO last_login_failure_count_user_id SET user_id=NEW.user_id, count=1 ON DUPLICATE KEY UPDATE count=count+1
        INSERT INTO last_login_failure_count_ip SET ip=NEW.ip, count=1                ON DUPLICATE KEY UPDATE count=count+1
    END IF;
END//
DELIMITER ;