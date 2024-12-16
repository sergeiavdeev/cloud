# Local starter
docker ps -aq --filter "name=config-server" | xargs -r docker rm -f
docker ps -aq --filter "name=gateway" | xargs -r docker rm -f
docker ps -aq --filter "name=eureka" | xargs -r docker rm -f
docker ps -aq --filter "name=gateway-prd" | xargs -r docker rm -f
docker system prune -a -f
mvn clean package
# docker pull sergeiavdeev/eureka:latest
# docker pull sergeiavdeev/gateway:latest
# docker pull sergeiavdeev/config-server:latest
docker build -t sergeiavdeev/eureka:1-dev eureka/
docker build -t sergeiavdeev/config-server:1-dev config-server/
docker build -t sergeiavdeev/gateway:1-dev gateway/
PROFILE=dev TAG=1-dev ENCRYPT_KEY=9edc7779-04e8-4275-ae43-ebedb8555b99 docker compose up -d
PROFILE=prd docker compose -f docker-compose-prd.yml up -d
docker system prune -a -f