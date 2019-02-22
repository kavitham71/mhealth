docker build -t mhealth -f Dockerfile-mhealth .
docker stop mhealth
docker rm mhealth
docker run -p 8080:8080/tcp -v mhealth-conf2:/app/conf -v mhealth-logs2:/app/logs -v /dev/urandom:/dev/random \
       --link mhealth-postgres:postgres --link mypart:mypart -d --name mhealth mhealth
docker exec -it mhealth tail -f logs/app.log

