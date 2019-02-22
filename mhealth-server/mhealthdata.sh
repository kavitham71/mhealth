docker build -t mhealthdata -f Dockerfile-mhealthdata .
docker stop mhealthdata
docker rm mhealthdata
docker run -p 8006:8006/tcp -v mhealthdata-conf2:/app/conf -v mhealthdata-logs2:/app/logs -v /dev/urandom:/dev/random \
       --link mhealth-postgres:postgres --link mypart:mypart -d --name mhealthdata mhealthdata
docker exec -it mhealthdata tail -f logs/app.log

