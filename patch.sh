comm -13 <(sort -u PID.txt) <(sort -u PPID.txt) > SUSPECT.txt
sort -n SUSPECT.txt > SUSPECT2.txt
rm SUSPECT.txt
mv SUSPECT2.txt SUSPECT.txt
