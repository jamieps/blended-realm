# Tomcat blended realm

An extension of a combined realm, which adds the following functionality:

- Authentication results, both positive and negative, are cached (in memory) for a configurable period.
- Additional roles are retrieved from the final realm specified, these are additive.

For example, a user can be authenticated against an LDAP directory but role information can be
retrieved from a different realm (e.g. from a database).

**Currently this is built against Tomcat 7, it is unlikely to work on other versions.**

## Configuration

There are two configuration items which control how long results are cached for:

- `cacheTimeUnits`: units of time which `cacheTime` is in, can be `MINUTES`, `HOURS`, `DAYS`.
- `cacheTime`: the time to cache results for

## Example configuration

```
            <Realm className="org.silverdream.apache.catalina.realm.BlendedRealm"
                    cacheTime="36" cacheTimeUnit="HOURS">
                <Realm className="org.apache.catalina.realm.JNDIRealm"
                       connectionURL="ldaps://127.0.0.1"
                       alternateURL="ldaps://127.0.0.1"
                       connectionName="foo"
                       connectionPassword="bar"
                       authentication="simple"
                       commonRole="user"                                                 
                       userBase="DC=example,DC=com"
                       userSubtree="true"
                       userSearch="(sAMAccountName={0})" />

                <!-- Hong Kong -->
                <Realm className="org.apache.catalina.realm.JNDIRealm"
                       connectionURL="ldaps://127.0.0.2"
                       alternateURL="ldaps://127.0.0.2"
                       connectionName="bar"
                       connectionPassword="foo"
                       authentication="simple"
                       commonRole="user"
                       userBase="DC=example,DC=com"
                       userSubtree="true"
                       userSearch="(sAMAccountName={0})" />
```

