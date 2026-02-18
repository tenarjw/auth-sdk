# mysql -u postfix -p
connect postfix;
INSERT INTO admin (username, password, superadmin, active)
VALUES ('postadmin@example.com', '{BCRYPT}$2y$10$...', 1, 1);
