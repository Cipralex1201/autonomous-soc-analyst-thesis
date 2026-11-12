for i in $(seq 1 600); do
    curl -s -o /dev/null \
      -w "%{http_code}\n" \
      "http://100.120.139.42/definitely-not-real-$i"
done
