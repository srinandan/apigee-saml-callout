HOST=ec2-174-129-47-34.compute-1.amazonaws.com
ORG=saml
ENV=prod
USR=opdk@apigee.com
PWD=$1


curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @apache-velocity-velocity-1.5.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=apache-velocity-velocity-1.5.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @bcprov-jdk15-130.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=bcprov-jdk15-130.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @commons-logging-1.2.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=commons-logging-1.2.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @esapi-2.1.0.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=esapi-2.1.0.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @joda-time-2.4.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=joda-time-2.4.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @open$ORG-2.5.3.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=open$ORG-2.5.3.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @openws-1.5.0.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=openws-1.5.0.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @org.apache.commons.collections.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=org.apache.commons.collections.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @slf4j-api-1.7.13.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=slf4j-api-1.7.13.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @slf4j-simple-1.7.13.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=slf4j-simple-1.7.13.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @xmlsec-1.5.5.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=xmlsec-1.5.5.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @xmltooling-1.3.4.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=xmltooling-1.3.4.jar&type=java" -i -v

curl -u $USR:$1 -H "Content-Type: application/octet-stream" --data-binary @commons-codec-1.10.jar -X POST "http://$HOST:8080/v1/organizations/$ORG/environments/$ENV/resourcefiles?name=commons-codec-1.10.jar&type=java" -i -v
