docker build -t mypart -f Dockerfile-mypart .
docker stop mypart
docker rm mypart
docker run -p 8003:8003/tcp \
  -v mypart-conf2:/app/conf \
  -v mypart-logs2:/app/logs \
  -v /dev/urandom:/dev/random \
  --link mypart-postgres:postgres \
  --add-host=smtp:171.65.65.5 \
  -d --name mypart mypart
docker exec -it mypart tail -f logs/app.log

