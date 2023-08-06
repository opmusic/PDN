docker run -d --name chrome1 -p 4443:4444 -v /dev/shm:/dev/shm selenium/standalone-chrome &
docker run -d --name chrome2 -p 4444:4444 -v /dev/shm:/dev/shm selenium/standalone-chrome &
docker run -d --name chrome3 -p 4445:4444 -v /dev/shm:/dev/shm selenium/standalone-chrome &
docker run -d --name chrome4 -p 4446:4444 -v /dev/shm:/dev/shm selenium/standalone-chrome &
docker run -d --name chrome5 -p 4447:4444 -v /dev/shm:/dev/shm selenium/standalone-chrome
