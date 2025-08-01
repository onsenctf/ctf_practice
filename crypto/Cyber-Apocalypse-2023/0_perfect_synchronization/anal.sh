unique_line=$(sort output.txt | uniq)
for line in $unique_line; do
  freq=$(grep -o $line output.txt | wc -l)
  p=$(echo "scale=4; $freq / 1479" | bc)
  echo -e "$p, $freq \t$line"
done
