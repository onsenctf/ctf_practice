#!/bin/bash

LPar="fbe86a428051747607a35b44b1a3e9e9"  # '{'
Ubar="a94f49727cf771a85831bd03af1caaf5"  # '_'
RPar="c53ba24fbbe9e3dbdd6062b3aab7ed1a"  # '}'
Space="61331054d82aeec9a20416759766d9d5" # ' '

cp output.txt tmp.txt
sed -i -e "s/$LPar/{/g; s/$Ubar/_/g; s/$RPar/}/g; s/$Space/ /g" tmp.txt

uniq=$(cat output.txt | sort | uniq | sed "/$LPar\|$Ubar\|$RPar\|$Space/d")

s="ABCDEFGHIJKLMNOPQRSTUVWXYZ" # {, }, 空白, _ は置換済みなので除外．

i=0
for l in $uniq; do
  echo "sed -i 's/$l/${s:i:1}/g' tmp.txt" | sh
  i=$(($i+1))
done

cat tmp.txt | tr -d '\n'
rm tmp.txt
