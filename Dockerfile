FROM openjdk:17-jdk-bullseye
COPY bin /opt/ldap/bin/
COPY lib /opt/ldap/lib/
ENTRYPOINT ["/opt/ldap/bin/ldap"]
