# sudo mariadb
CREATE DATABASE postfix;
CREATE USER 'postfix'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON postfix.* TO 'postfix'@'localhost';
FLUSH PRIVILEGES;
quit
