#!/usr/bin/env bash
#!CMD: ./solve.sh

grep -oP "[a-z0-9]+.attacker.com" "./export.txt" | uniq | perl -pe "s/\.attacker\.com\n//g" | xxd -r -p | rg -oP "pascalCTF{.*}"
