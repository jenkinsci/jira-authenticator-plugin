package org.jenkinsci.plugins.jiraauthenticator;

import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.jiraauthenticator.beans.JiraResponseGeneral;

import com.google.gson.Gson;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import com.sun.jersey.client.urlconnection.HTTPSProperties;

import hudson.util.Secret;

/**
 * Service class wraps the functionality to connect to a Jira instance. This class makes use of a technical user that is
 * used to contact Jira.
 * 
 * @author stephan.watermeyer
 *
 */
public class JiraAuthenticationService {

    private static final String PARAM_VAL_GROUPS = "groups";
    private static final String PARAM_KEY_EXPAND = "expand";
    private static final String PARAM_KEY_USERNAME = "username";

    private static final Logger LOG = Logger.getLogger(JiraSecurityRealm.class.getName());
    private final String mUrl;
    private final String mTechnicalUserName;
    private final Secret mTechnicalUserPassword;
    private final Integer mTimeoutInMS;
    private final boolean mInsecureConnection;

    /**
     * Default constructor.
     * 
     * @param pURL
     *            the URL of Jira.
     * @param pTechnicalUserName
     *            technical user name
     * @param pTechnicalUserPassword
     *            password of the technical user.
     * @param pTimeoutInMS
     *            timeout in MS
     * @param pInsecureConnections
     *            TRUE to allow insecure TLS connections.
     */
    public JiraAuthenticationService(String pURL, String pTechnicalUserName, Secret pTechnicalUserPassword, Integer pTimeoutInMS, boolean pInsecureConnections) {
        super();
        this.mUrl = pURL;
        this.mTechnicalUserName = pTechnicalUserName;
        this.mTechnicalUserPassword = pTechnicalUserPassword;
        this.mTimeoutInMS = pTimeoutInMS;
        this.mInsecureConnection = pInsecureConnections;
    }

    /**
     * Get a user groups
     * 
     * @param pUsername
     *            the user whos groups should be loaded
     * @return response from Jira
     * @throws AuthenticationException
     *             TBD.
     */
    public JiraResponseGeneral loadUserByUsername(final String pUsername) throws AuthenticationException {
        final MultivaluedMap<String, String> requestParams = new MultivaluedHashMap<String, String>();
        requestParams.putSingle(PARAM_KEY_USERNAME, pUsername);
        requestParams.putSingle(PARAM_KEY_EXPAND, PARAM_VAL_GROUPS);

        // use the technical user to retrieve the groups of a given username.
        return callService(mTechnicalUserName, mTechnicalUserPassword.getPlainText(), requestParams);
    }

    /**
     * To authenticate a user.
     * 
     * @param pUsername
     *            the users username.
     * @param pPassword
     *            the users password in clear text.
     * @return the parsed response from Jira
     * @throws AuthenticationException
     *             if something goes wrong.
     */
    public JiraResponseGeneral authenticate(final String pUsername, final String pPassword) throws AuthenticationException {
        final MultivaluedMap<String, String> requestParams = new MultivaluedHashMap<String, String>();
        requestParams.putSingle(PARAM_KEY_USERNAME, pUsername);

        // here we pass the given credentials. because we dont want to authorize the technical user
        return callService(pUsername, pPassword, requestParams);
    }

    JiraResponseGeneral callService(final String pUsername, final String pPassword, MultivaluedMap<String, String> pRequestParams) {
        try {
            ClientConfig config = initSSLConfig(mInsecureConnection);
            Client client = Client.create(config);

            if (StringUtils.isNotEmpty(pUsername) && StringUtils.isNotEmpty(pPassword)) {
                LOG.fine("setting username to: " + pUsername);
                client.addFilter(new HTTPBasicAuthFilter(pUsername, pPassword));
            } else {
                throw new AuthenticationServiceException("no username and password provided");
            }

            client.setReadTimeout(mTimeoutInMS);
            WebResource mInstance = client.resource(UriBuilder.fromUri(mUrl).build());
            mInstance = mInstance.path("rest/api/2/user/");

            final String serviceResponse = mInstance.queryParams(pRequestParams).accept(MediaType.APPLICATION_JSON).get(String.class);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine(serviceResponse.toString());
            }

            JiraResponseGeneral parsedResponsed = new Gson().fromJson(serviceResponse, JiraResponseGeneral.class);

            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine(parsedResponsed.toString());
            }

            return parsedResponsed;
        } catch (ClientHandlerException e) {
            if (e.getCause() != null && e.getCause() instanceof SocketTimeoutException) {
                throw new AuthenticationServiceException("Timeout limit reached while contacing Jira: " + mTimeoutInMS + "ms", e);
            } else {
                LOG.log(Level.WARNING, "the answer from jira is unexpected: " + e.getMessage(), e);
                throw new AuthenticationServiceException("format error: " + e.getMessage(), e);
            }
        } catch (UniformInterfaceException e) {
            if (e.getMessage().contains("403")) {
                throw new BadCredentialsException("User does not exist (HTTP 403): " + pUsername, e);
            } else if (e.getMessage().contains("401")) {
                throw new BadCredentialsException("User is not allowed (HTTP 401): " + pUsername, e);
            } else {
                LOG.log(Level.WARNING, "response error: " + e.getMessage(), e);
                throw new AuthenticationServiceException("response error: " + e.getMessage(), e);
            }
        } catch (Exception e) {
            throw new AuthenticationServiceException("general error: " + e.getMessage(), e);
        }
    }

    ClientConfig initSSLConfig(boolean pAllowInsecureConnections) throws NoSuchAlgorithmException, KeyManagementException {
        final ClientConfig config = new DefaultClientConfig();
        if (pAllowInsecureConnections) {
            LOG.log(Level.INFO, "connection to Jira services is using an insecure connection");
            SSLContext ctx = SSLContext.getInstance("SSL");
            ctx.init(null, new TrustManager[] {new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }}, null);
            config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(HttpsURLConnection.getDefaultHostnameVerifier(), ctx));
        } else {
            LOG.log(Level.FINER, "connection to Jira services is secured");
        }
        return config;
    }

}
