drop table if exists logins;
create table logins (
    pid char(36) primary key,
    username varchar(64) unique not null,
    pw binary(64) not null,
    salt binary(32) not null
) ENGINE innodb;

drop procedure if exists byUsername;

delimiter //

create procedure byUsername (in userId varchar(64))
    begin
        select pid, pw, salt from logins where username=userId;
    end//

delimiter ;