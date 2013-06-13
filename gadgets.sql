
CREATE TABLE gadgets(
address INT8,
opcode  VARCHAR(16),
arg1    VARCHAR(16),
arg2    VARCHAR(16),
bin     VARCHAR(8),
ret_addr VARCHAR(8),
ret_distance VARCHAR(8),
next_ret_address INT8
) ;

CREATE TABLE dll_info(
name VARCHAR(32),
path VARCHAR(128),
md5 VARCHAR(32),
sha512 VARCHAR(128),
cpu VARCHAR(32),
size INT32
) ;

CREATE TABLE builder(
address INT8 primary key,
description TEXT,
dst VARCHAR(16),
value INT64,
num INT8
) ;

CREATE TABLE expressions(
		id INT8,
		lexpr VARCHAR(128),
		rexpr VARCHAR(128)
);

CREATE TABLE expression_gadget(
		address INT8,
		expression INT8
);
