docker ps -aq --filter "name=config-server" | xargs -r docker rm -f
docker ps -aq --filter "name=gateway" | xargs -r docker rm -f
docker ps -aq --filter "name=eureka" | xargs -r docker rm -f
docker pull sergeiavdeev/eureka:latest
docker pull sergeiavdeev/gateway:latest
docker pull sergeiavdeev/config-server:latest
PROFILE=dev ENCRYPT_KEY=9edc7779-04e8-4275-ae43-ebedb8555b99 docker compose up -d
docker system prune -a -f