#!/bin/sh

exec wireshark -X "lua_script:`dirname $0`/epson-beamer.lua" "$@"
