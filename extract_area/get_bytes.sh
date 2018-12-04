./bin2hex --i $1 --o raw_bytes
cat raw_bytes | xclip -selection c
echo "copyed to clipboard"
