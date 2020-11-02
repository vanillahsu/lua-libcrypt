/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020, San-Tai Hsu <vanilla@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/lib/flua/libjail/lua_jail.c 367013 2020-10-24 17:08:59Z freqlabs $
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/lib/flua/libjail/lua_jail.c 367013 2020-10-24 17:08:59Z freqlabs $");

#include <sys/param.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int luaopen_crypt(lua_State *);

static int
lua_crypt(lua_State *L)
{
	const char *password, *hash;
	struct crypt_data *buffer;
	char *ret;

	buffer = malloc(sizeof(*buffer));
	if (buffer == NULL) {
		return luaL_error(L, "malloc error");
	}

	memset(buffer, 0, sizeof(*buffer));
	password = luaL_checkstring(L, 1);
	hash = luaL_checkstring(L, 2);

	ret = crypt_r(password, hash, buffer);
	if (ret == NULL) {
		return luaL_error(L, "fail to crypt");
	}

	lua_pushstring(L, ret);
	free(buffer);

	return (1);
}

static int
lua_set_format(lua_State *L)
{
	int ret, format;

	format = luaL_checkinteger(L, 1);
	switch(format) {
		case 6:
			ret = crypt_set_format("sha512");
			break;
		case 5:
			ret = crypt_set_format("sha256");
			break;
		case 3:
			ret = crypt_set_format("nth");
			break;
		case 2:
			ret = crypt_set_format("blf");
			break;
		case 1:
			ret = crypt_set_format("md5");
			break;
		default:
		case 0:
			ret = crypt_set_format("des");
	}

	lua_pushinteger(L, ret);

	return(1);
}

static int
lua_get_format(lua_State *L)
{
	const char *format;

	format = crypt_get_format();
	lua_pushstring(L, format);
	return (1);
}

static const struct luaL_Reg l_crypt[] = {
	{"crypt", lua_crypt},
	{"set_format", lua_set_format},
	{"get_format", lua_get_format},
	{NULL, NULL}
};

int
luaopen_crypt(lua_State *L)
{
	lua_newtable(L);

	luaL_setfuncs(L, l_crypt, 0);

	lua_pushinteger(L, 0);
	lua_setfield(L, -2, "DES");
	lua_pushinteger(L, 1);
	lua_setfield(L, -2, "MD5");
	lua_pushinteger(L, 2);
	lua_setfield(L, -2, "BlowFish");
	lua_pushinteger(L, 3);
	lua_setfield(L, -2, "NTHash");
	lua_pushinteger(L, 5);
	lua_setfield(L, -2, "SHA256");
	lua_pushinteger(L, 6);
	lua_setfield(L, -2, "SHA512");

	return (1);
}
