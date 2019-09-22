# How to run docker container

1. Build docker image from project folder

    `docker build -t lab1:latest .`

2. Run container from project folder

    `docker run -d -v $(pwd):/code -p 8080:8080 --name lab1 lab1:latest`

3. Then you should be able to hit http://localhost:8080 form local machine

Note: I had to change the hostname from `localhost` to `0.0.0.0` to expose the API
