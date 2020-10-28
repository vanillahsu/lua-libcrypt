# $FreeBSD: head/lib/flua/libjail/Makefile 367013 2020-10-24 17:08:59Z freqlabs $

SHLIB_NAME=	crypt.so
SHLIBDIR=	${LIBDIR}/flua

SRCS+=		lua_crypt.c

CFLAGS+= \
	-I${SRCTOP}/contrib/lua/src \
	-I${SRCTOP}/lib/liblua \

LIBADD+=	crypt

.include <bsd.lib.mk>
