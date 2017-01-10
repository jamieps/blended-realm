# tomcat-blended-realm

Tomcat combined realm which caches the authentication result for a configurable period.

Roles are retrieved from the final realm specified, these are additive.

Both positive and negative results are cached.

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

