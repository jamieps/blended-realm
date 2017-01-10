/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.silverdream.apache.catalina.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.management.ObjectName;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.catalina.*;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

/**
 * Realm implementation that should contain at least two realms. Authentication is
 * attempted against all realms in the order they were configured. If any realm,
 * apart from the last realm, authenticates the user, authentication succeeds.
 *
 * <p>
 *     Role information is retrieved from the final realm specified.
 *     This augments any roles provided by earlier realms.
 *     The password used for the role realm is always empty.
 * </p>
 *
 * <p>
 *     The realm which successfully authenticated the user is cached for
 *     a configurable period, by default this is 1 day.
 * </p>
 */
public class BlendedRealm extends RealmBase {
    private Cache<String, Optional<GenericPrincipal>> authCache;
    private Cache<X509Certificate[], Optional<GenericPrincipal>> certCache;
    private Cache<GSSContext, Optional<GenericPrincipal>> gssCtxCache;
    private String cacheTimeUnit;
    private int cacheTime;

    private static final Log log = LogFactory.getLog(BlendedRealm.class);

    /**
     * The list of Realms contained by this Realm.
     */
    protected List<Realm> realms = new LinkedList<>();

    /**
     * Descriptive information about this Realm implementation.
     */
    protected static final String name = "BlendedRealm";

    /**
     * The unit of time that cache time represents.
     *
     * @return  the unit of time
     */
    public String getCacheTimeUnit() {
        return this.cacheTimeUnit;
    }


    /**
     * Set the cache time unit.
     *
     * @param   cacheTimeUnit   the unit of time
     */
    public void setCacheTimeUnit(String cacheTimeUnit) {
        this.cacheTimeUnit = cacheTimeUnit;
    }


    /**
     * Get the time to cache results for.
     *
     * @return  the time to cache
     */
    public int getCacheTime() {
        return this.cacheTime;
    }


    /**
     * Set the time to cache results for.
     *
     * @param   cacheTime   the time to cache
     */
    public void setCacheTime(int cacheTime) {
        this.cacheTime = cacheTime;
    }


    /**
     * Add a realm to the list of realms that will be used to authenticate
     * users.
     */
    public void addRealm(Realm theRealm) {
        realms.add(theRealm);

        if (log.isDebugEnabled()) {
            log.debug(sm.getString("extRoleCombinedRealm.addRealm", theRealm.getInfo(),
                    Integer.toString(realms.size())));
        }
    }


    /**
     * Return the set of Realms that this Realm is wrapping
     */
    public ObjectName[] getRealms() {
        ObjectName[] result = new ObjectName[realms.size()];
        for (Realm realm : realms) {
            if (realm instanceof RealmBase) {
                result[realms.indexOf(realm)] =
                        ((RealmBase) realm).getObjectName();
            }
        }
        return result;
    }


    /**
     * Return the Principal associated with the specified username, which
     * matches the digest calculated using the given parameters using the
     * method described in RFC 2069; otherwise return <code>null</code>.
     *
     * @param username Username of the Principal to look up
     * @param clientDigest Digest which has been submitted by the client
     * @param nonce Unique (or supposedly unique) token which has been used
     * for this request
     * @param realmName Realm name
     * @param md5a2 Second MD5 digest used to calculate the digest :
     * MD5(Method + ":" + uri)
     */
    @Override
    public Principal authenticate(String username, String clientDigest,
                                  String nonce, String nc, String cnonce, String qop,
                                  String realmName, String md5a2) {
        String key = username + ":" + clientDigest + ":" + realmName + ":" + md5a2;
        Optional<GenericPrincipal> principal = Optional.empty();

        try {
             principal = authCache.get(key, () -> {
                GenericPrincipal authenticatedUser = null;

                for (Realm realm : realms) {
                    authenticatedUser = (GenericPrincipal) realm.authenticate(username,
                            clientDigest, nonce, nc, cnonce, qop, realmName, md5a2);
                    authenticatedUser = checkAuthentication(realm, username, authenticatedUser);
                    if (authenticatedUser != null) {
                        break;
                    }
                }

                return Optional.ofNullable(authenticatedUser);
            });
        } catch (ExecutionException e) {
            log.error(e);
        }

        return principal.orElse(null);
    }


    /**
     * Return the Principal associated with the specified username and
     * credentials, if there is one; otherwise return <code>null</code>.
     *
     * @param username Username of the Principal to look up
     * @param credentials Password or other credentials to use in
     *  authenticating this username
     */
    @Override
    public Principal authenticate(String username, String credentials) {
        String key = username + ":" + credentials;
        Optional<GenericPrincipal> principal = Optional.empty();

        try {
            principal = authCache.get(key, () -> {
                GenericPrincipal authenticatedUser = null;

                for (Realm realm : realms) {
                    authenticatedUser = (GenericPrincipal)realm.authenticate(username, credentials);
                    authenticatedUser = checkAuthentication(realm, username, authenticatedUser);
                    if (authenticatedUser != null) {
                        break;
                    }
                }

                return Optional.ofNullable(authenticatedUser);
            });
        } catch (ExecutionException e) {
            log.error(e);
        }

        return principal.orElse(null);
    }


    /**
     * Set the Container with which this Realm has been associated.
     *
     * @param container The associated Container
     */
    @Override
    public void setContainer(Container container) {
        for (Realm realm : realms) {
            // Set the realmPath for JMX naming
            if (realm instanceof RealmBase) {
                ((RealmBase) realm).setRealmPath(
                        getRealmPath() + "/realm" + realms.indexOf(realm));
            }

            // Set the container for sub-realms. Mainly so logging works.
            realm.setContainer(container);
        }
        super.setContainer(container);
    }


    /**
     * Prepare for the beginning of active use of the public methods of this
     * component and implement the requirements of
     * {@link org.apache.catalina.util.LifecycleBase#startInternal()}.
     *
     * @exception LifecycleException if this component detects a fatal error
     *  that prevents this component from being used
     */
    @Override
    protected void startInternal() throws LifecycleException {
        String timeUnitStr  = getCacheTimeUnit();
        TimeUnit timeUnit   = TimeUnit.HOURS;
        int cacheTime       = getCacheTime();
        if (!Arrays.asList(TimeUnit.values()).contains(timeUnitStr)) {
            log.info("Cache time unit defaulted to hours");
        } else {
            timeUnit = TimeUnit.valueOf(timeUnitStr);
        }
        if (cacheTime < 1) {
            cacheTime = 1;
        }

        log.info("Authentication results will be cached for: " + cacheTime + " " + timeUnit);
        this.authCache      = CacheBuilder.newBuilder()
                .expireAfterWrite(cacheTime, timeUnit)
                .build();
        this.certCache      = CacheBuilder.newBuilder()
                .expireAfterWrite(cacheTime, timeUnit)
                .build();
        this.gssCtxCache    = CacheBuilder.newBuilder()
                .expireAfterWrite(cacheTime, timeUnit)
                .build();

        // Start 'sub-realms' then this one
        Iterator<Realm> iter = realms.iterator();

        while (iter.hasNext()) {
            Realm realm = iter.next();
            if (realm instanceof Lifecycle) {
                try {
                    ((Lifecycle) realm).start();
                } catch (LifecycleException e) {
                    // If realm doesn't start can't authenticate against it
                    iter.remove();
                    log.error(sm.getString("extRoleCombinedRealm.realmStartFail",
                            realm.getInfo()), e);
                }
            }
        }
        super.startInternal();
    }


    /**
     * Gracefully terminate the active use of the public methods of this
     * component and implement the requirements of
     * {@link org.apache.catalina.util.LifecycleBase#stopInternal()}.
     *
     * @exception LifecycleException if this component detects a fatal error
     *  that needs to be reported
     */
    @Override
    protected void stopInternal() throws LifecycleException {
        authCache.cleanUp();
        certCache.cleanUp();
        gssCtxCache.cleanUp();

        // Stop this realm, then the sub-realms (reverse order to start)
        super.stopInternal();
        for (Realm realm : realms) {
            if (realm instanceof Lifecycle) {
                ((Lifecycle) realm).stop();
            }
        }
    }


    /**
     * Ensure child Realms are destroyed when this Realm is destroyed.
     */
    @Override
    protected void destroyInternal() throws LifecycleException {
        for (Realm realm : realms) {
            if (realm instanceof Lifecycle) {
                ((Lifecycle) realm).destroy();
            }
        }
        super.destroyInternal();
    }


    /**
     * Delegate the backgroundProcess call to all sub-realms.
     */
    @Override
    public void backgroundProcess() {
        super.backgroundProcess();

        for (Realm r : realms) {
            r.backgroundProcess();
        }
    }

    /**
     * Return the Principal associated with the specified chain of X509
     * client certificates.  If there is none, return <code>null</code>.
     *
     * @param certs Array of client certificates, with the first one in
     *  the array being the certificate of the client itself.
     */
    @Override
    public Principal authenticate(X509Certificate[] certs) {
        Optional<GenericPrincipal> principal = Optional.empty();

        try {
            principal = certCache.get(certs, () -> {
                GenericPrincipal authenticatedUser = null;

                String username = null;
                if (certs != null && certs.length > 0) {
                    username = certs[0].getSubjectDN().getName();
                }

                for (Realm realm : realms) {
                    authenticatedUser = (GenericPrincipal)realm.authenticate(certs);
                    authenticatedUser = checkAuthentication(realm, username, authenticatedUser);
                    if (authenticatedUser != null) {
                        break;
                    }
                }

                return Optional.ofNullable(authenticatedUser);
            });
        } catch (ExecutionException e) {
            log.error(e);
        }

        return principal.orElse(null);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Principal authenticate(GSSContext gssContext, boolean storeCreds) {
        if (gssContext.isEstablished()) {
            Optional<GenericPrincipal> principal = Optional.empty();

            try {
                principal = gssCtxCache.get(gssContext, () -> {
                    GenericPrincipal authenticatedUser = null;
                    String username;
                    GSSName name;
                    try {
                        name = gssContext.getSrcName();
                    } catch (GSSException e) {
                        log.warn(sm.getString("realmBase.gssNameFail"), e);
                        return null;
                    }

                    username = name.toString();

                    for (Realm realm : realms) {
                        authenticatedUser = (GenericPrincipal) realm.authenticate(gssContext,
                                storeCreds);
                        authenticatedUser = checkAuthentication(realm, username, authenticatedUser);
                        if (authenticatedUser != null) {
                            break;
                        }
                    }

                    return Optional.ofNullable(authenticatedUser);
                });
            } catch (ExecutionException e) {
                log.error(e);
            }

            return principal.orElse(null);
        }

        // Fail in all other cases
        return null;
    }

    @Override
    protected String getName() {
        return name;
    }

    @Override
    protected String getPassword(String username) {
        // This method should never be called
        // Stack trace will show where this was called from
        UnsupportedOperationException uoe =
                new UnsupportedOperationException(
                        sm.getString("extRoleCombinedRealm.getPassword"));
        log.error(sm.getString("extRoleCombinedRealm.unexpectedMethod"), uoe);
        throw uoe;
    }

    @Override
    protected Principal getPrincipal(String username) {
        // This method should never be called
        // Stack trace will show where this was called from
        UnsupportedOperationException uoe =
                new UnsupportedOperationException(
                        sm.getString("extRoleCombinedRealm.getPrincipal"));
        log.error(sm.getString("extRoleCombinedRealm.unexpectedMethod"), uoe);
        throw uoe;
    }

    /**
     * Check if the user authenticated successfully, if so retrieve additional
     * roles from the final realm specified.
     *
     * @param   authRealm           realm to authenticate against
     * @param   username            the name of the user
     * @param   authenticatedUser   the principal returned by the realm
     * @return  the principal, with any additional roles, or null if authentication fails
     */
    private GenericPrincipal checkAuthentication(Realm authRealm, String username,
                                          GenericPrincipal authenticatedUser) {
        if (log.isDebugEnabled()) {
            log.debug(sm.getString("extRoleCombinedRealm.authStart", username,
                    authRealm.getClass().getName()));
        }

        // Last realm specified provides role information
        Realm roleRealm = realms.get(realms.size()-1);

        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("extRoleCombinedRealm.authFail", username,
                        authRealm.getClass().getName()));
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("extRoleCombinedRealm.authSuccess",
                        username, authRealm.getClass().getName()));
            }

            String password = authenticatedUser.getPassword();
            List<String> roles = new ArrayList<>();
            roles.addAll(Arrays.asList(authenticatedUser.getRoles()));

            // Get additional role(s) from the second defined realm
            GenericPrincipal roleUser =
                    (GenericPrincipal)roleRealm.authenticate(username, "");

            if (roleUser != null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("extRoleCombinedRealm.authSuccess",
                            username, roleRealm.getClass().getName()));
                }

                roles.addAll(Arrays.asList(roleUser.getRoles()));

                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("extRoleCombinedRealm.roles",
                            username, roles));
                }

                authenticatedUser = new GenericPrincipal(username, password, roles);
            }
        }

        return authenticatedUser;
    }
}
