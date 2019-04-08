#!/bin/bash
rm -f *.cfg
./bcadmin -c . create public.toml --interval 500ms
./phapp spawner bc-* key-*
./bcadmin show --bc bc-*
./bcadmin key -print key-*
