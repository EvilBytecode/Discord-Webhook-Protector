curl -X SIGMA "http://localhost/index.php" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "User-Agent: Unix-Client" \
  -d "{\"api_key\": \"your-api-key\", \"embeds\": [{\"title\": \"Greeting from Unix\", \"description\": \"Hello, Discord!\", \"color\": 5620992}], \"ip\": \"your-ip-address\"}"
