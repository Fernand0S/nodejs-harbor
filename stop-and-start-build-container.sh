#!/bin/bash
#Description
#Autor: Antônio Santana
#Data: 07032026

#Removendo containers
docker rm -f harbor-teams-webhook

#Realiza novo buid
 docker build -t harbor-teams-webhook .

#Start Container
 docker run -d \
-p 5000:5000 \
-e NODE_TLS_REJECT_UNAUTHORIZED=0 \
-e HARBOR_URL=https://harbor-qa.acelen.corp \
-e HARBOR_USER='XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' \
-e HARBOR_PASSWORD=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
-e TEAMS_WEBHOOK=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\                                                                                       955a67b00804d439be059782fe86f27/c0a43daa-7186-4eed-9e6d-162834c5ee18/V273cUiBjmi                                                                                        MF-qHOW47ItnvN3TG6KW4-QZynIEc1tmkI1 \
--name harbor-teams-webhook \
harbor-teams-webhook
