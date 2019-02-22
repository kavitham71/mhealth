docker build -t mhealthadmin -f Dockerfile-mhealthadmin .
docker stop mhealthadmin
docker rm mhealthadmin
docker run -p 8007:8007/tcp -v mhealthadmin-conf2:/app/conf -v mhealthadmin-logs2:/app/logs -v /dev/urandom:/dev/random \
       --link mypart-postgres:postgres -d --name mhealthadmin mhealthadmin
docker exec -it mhealthadmin tail -f logs/app.log

