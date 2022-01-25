#!/bin/bash
set -e
docker pull gradle:jdk11
TAG=${1:-main}
TDIR=`mktemp -d`
echo $TDIR
function finish {
  rm -rf $TDIR
}
trap finish EXIT
cd $TDIR
git clone https://github.com/agebe/ldap.git
if [ $TAG = 'main' ]; then
  echo "build from main"
  DOCKER_TAG='latest'
else
  echo "build from $TAG"
  ( cd ldap && git checkout tags/$TAG )
  DOCKER_TAG=$TAG
fi
docker run --rm -ti -u gradle --name "ldap-build" -v "$PWD/ldap":/home/gradle/project -w /home/gradle/project -e "GRADLE_USER_HOME=/home/gradle/project/.gradle" gradle:jdk11 bash -c "gradle dockerPrepare"
( cd ldap/build/docker && docker build --pull -t ldap:$DOCKER_TAG . )
echo done
