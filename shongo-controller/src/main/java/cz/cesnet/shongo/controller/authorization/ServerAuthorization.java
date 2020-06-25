package cz.cesnet.shongo.controller.authorization;


import cz.cesnet.shongo.CommonReportSet;
import cz.cesnet.shongo.api.UserInformation;
import cz.cesnet.shongo.controller.ControllerConfiguration;
import cz.cesnet.shongo.controller.ControllerReportSet;
import cz.cesnet.shongo.controller.api.Group;
import cz.cesnet.shongo.controller.api.SecurityToken;
import cz.cesnet.shongo.report.ReportRuntimeException;
import cz.cesnet.shongo.ssl.ConfiguredSSLContext;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.apache.ws.commons.util.Base64;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.ObjectNode;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.persistence.EntityManagerFactory;
import java.io.*;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/**
 * Provides methods for performing authentication and authorization.
 *
 * @author Martin Srom <martin.srom@cesnet.cz>
 */
public class ServerAuthorization extends Authorization
{
    private static Logger logger = LoggerFactory.getLogger(ServerAuthorization.class);

    /**
     * Authentication service path in auth-server.
     */
    private static final String AUTHENTICATION_SERVICE_PATH = "/authn/oic";

    /**
     * @see cz.cesnet.shongo.controller.ControllerConfiguration
     */
    private ControllerConfiguration configuration;

    /**
     * Access token which won't be verified and can be used for testing purposes.
     */
    private String rootAccessToken;

    /**
     * URL to authorization server.
     */
    private String authorizationServer;

    /**
     * URL to LDAP authorization server.
     */
    private String ldapAuthorizationServer;

    /**
     * Authorization header for requests.
     */
    private String requestAuthorizationHeader;

    /**
     * {@link HttpClient} for performing auth-server requests.
     */
    private HttpClient httpClient;

    /**
     * @see ObjectMapper
     */
    private ObjectMapper jsonMapper = new ObjectMapper();

    /**
     * Constructor.
     *
     * @param configuration        to load authorization configuration from
     * @param entityManagerFactory
     */
    private ServerAuthorization(ControllerConfiguration configuration, EntityManagerFactory entityManagerFactory)
    {
        super(configuration, entityManagerFactory);

        // Debug HTTP requests
        //System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        //System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        //System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");
        //System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");

        this.configuration = configuration;

        // Authorization server
        authorizationServer = configuration.getString(ControllerConfiguration.SECURITY_SERVER);
        if (authorizationServer == null) {
            throw new IllegalStateException("Authorization server is not set in the configuration.");
        }
        ldapAuthorizationServer = configuration.getString(ControllerConfiguration.SECURITY_LDAP_SERVER);
        if (ldapAuthorizationServer == null) {
            throw new IllegalStateException("LDAP authorization server is not set in the configuration.");
        }
        logger.info("Using authorization server '{}'.", authorizationServer);
        logger.info("Using LDAP authorization server '{}'.", ldapAuthorizationServer);

        // Authorization header

        String clientId = configuration.getString(ControllerConfiguration.SECURITY_CLIENT_ID);
        String clientSecret = configuration.getString(ControllerConfiguration.SECURITY_CLIENT_SECRET);
        String clientAuthorization = clientId + ":" + clientSecret;
        byte[] bytes = clientAuthorization.getBytes();
        requestAuthorizationHeader = "Basic " + Base64.encode(bytes, 0, bytes.length, 0, "");

        // Create http client
        httpClient = ConfiguredSSLContext.getInstance().createHttpClient();

        initialize();
    }

    /**
     * Initialize {@link #rootAccessToken}.
     */
    public void initRootAccessToken()
    {
        // Root access token
        rootAccessToken = new BigInteger(160, new SecureRandom()).toString(16);
        String rootAccessTokenFile = configuration.getString(ControllerConfiguration.SECURITY_ROOT_ACCESS_TOKEN_FILE);
        if (rootAccessTokenFile != null) {
            writeRootAccessToken(rootAccessTokenFile, rootAccessToken);
        }
        administrationModeByAccessToken.put(rootAccessToken, AdministrationMode.ADMINISTRATOR);
    }

    /**
     * @return url to authentication service in auth-server
     */
    private String getAuthenticationUrl()
    {
        return authorizationServer + AUTHENTICATION_SERVICE_PATH;
    }

    @Override
    protected UserInformation onValidate(SecurityToken securityToken)
    {
        // Always allow testing access token
        if (rootAccessToken != null && securityToken.getAccessToken().equals(rootAccessToken)) {
            logger.trace("Access token '{}' is valid for testing.", securityToken.getAccessToken());
            return ROOT_USER_DATA.getUserInformation();
        }
        return super.onValidate(securityToken);
    }

    @Override
    protected UserData onGetUserDataByAccessToken(String accessToken)
            throws ControllerReportSet.UserNotExistsException
    {
        // Testing security token represents root user
        if (rootAccessToken != null && accessToken.equals(rootAccessToken)) {
            return ROOT_USER_DATA;
        }

        Exception errorException = null;
        String errorReason = null;
        try {
            URIBuilder uriBuilder = new URIBuilder(getAuthenticationUrl() + "/userinfo");
            uriBuilder.setParameter("schema", "openid");
            HttpGet httpGet = new HttpGet(uriBuilder.build());
            httpGet.setHeader("Authorization", "Bearer " + accessToken);
            HttpResponse response = httpClient.execute(httpGet);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                JsonNode jsonNode = readJson(response.getEntity());
                if (jsonNode == null) {
                    throw new ControllerReportSet.UserNotExistsException(accessToken);
                }
                String userId = getIdFromOIDCResponse(jsonNode);
                Collection<UserInformation> userInformationCollection = this.listUserInformation(new HashSet<String>(Arrays.asList(userId)), null);
                Iterator<UserInformation> iterator = userInformationCollection.iterator();
                if (!iterator.hasNext()) {
                    throw new ControllerReportSet.UserNotExistsException(userId);
                }
                UserInformation ldapUserInformation = iterator.next();
                UserData userData = new UserData();
                UserInformation newUserInformation = userData.getUserInformation();
                newUserInformation.setUserId(ldapUserInformation.getUserId());
                newUserInformation.setFirstName(ldapUserInformation.getFirstName());
                newUserInformation.setLastName(ldapUserInformation.getLastName());
                newUserInformation.setPrincipalNames(ldapUserInformation.getPrincipalNames());
                newUserInformation.setEmail(ldapUserInformation.getEmail());
                return userData;
            }
            else {
                JsonNode jsonNode = readJson(response.getEntity());
                if (jsonNode != null) {
                    String error = jsonNode.get("error").getTextValue();
                    String errorDescription = jsonNode.get("error_description").getTextValue();
                    if (error.contains("invalid_token")) {
                        throw new ControllerReportSet.SecurityInvalidTokenException(accessToken);
                    }
                    errorReason = String.format("%s, %s", error, errorDescription);
                }
                else {
                    errorReason = "unknown";
                }
            }
        }
        catch (ControllerReportSet.SecurityInvalidTokenException exception) {
            throw exception;
        }
        catch (ControllerReportSet.UserNotExistsException exception) {
            throw exception;
        }
        catch (Exception exception) {
            errorException = exception;
        }
        // Handle error
        String errorMessage = String.format("Retrieving user information by access token '%s' failed.", accessToken);
        if (errorReason != null) {
            errorMessage += " " + errorReason;
        }
        throw new RuntimeException(errorMessage, errorException);
    }

    protected String getIdFromOIDCResponse (JsonNode jsonNode) {
        if (!jsonNode.has("original_id")) {
            throw new IllegalArgumentException("Token endpoint did not return original_id.");
        }

        // Parse cuniPersonalId
        String userId;

        String originalId = jsonNode.get("original_id").getTextValue();
        if (!originalId.endsWith("@cuni.cz")) {
            throw new IllegalArgumentException("Unable to parse cuniPersonalId from original_id.");
        } else {
            userId = originalId.replace("@cuni.cz", "");
        }
        return userId;
    }

    @Override
    protected UserData onGetUserDataByUserId(final String userId)
            throws ControllerReportSet.UserNotExistsException
    {
        String filter = "uid=" + userId;
        SearchControls ctrls = new SearchControls();
        ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        ctrls.setCountLimit(1);

        DirContext ctx = null;
        NamingEnumeration results = null;
        UserData userData;

        try {
            ctx = getLdapContext();
            results = ctx.search("", filter, ctrls);
            if (results.hasMore()) {
                SearchResult result = (SearchResult) results.next();
                userData = createUserDataFromLdapData(result.getAttributes());
            } else {
                throw new ControllerReportSet.UserNotExistsException(userId);
            }
        } catch (NamingException e) {
            throw new ControllerReportSet.UserNotExistsException(userId);
        } finally {
            try {
                if (results != null) {
                    results.close();
                }
                if (ctx != null) {
                    ctx.close();
                }
            }
            catch (Exception ignored) {
                // Ignore.
            }
        }
        return userData;
    }

    @Override
    protected String onGetUserIdByPrincipalName(final String principalName)
            throws ControllerReportSet.UserNotExistsException
    {
        String userId;
        if (principalName.endsWith("@cuni.cz")) {
            userId = principalName.replace("@cuni.cz", "");
        } else {
            throw new IllegalArgumentException("Invalid format of principal name: " + principalName);
        }
        return userId;
    }

    @Override
    protected Collection<UserData> onListUserData(final Set<String> filterUserIds, String search)
    {
        StringBuilder filter = new StringBuilder();
        SearchControls ctrls = new SearchControls();
        ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        DirContext ctx = null;
        NamingEnumeration results = null;
        List<UserData> userDataList = new LinkedList<>();

        if (filterUserIds != null && filterUserIds.size() > 0) {
            filter.append("(|");
            for (String id : filterUserIds) {
                filter.append("(uid=" + id + ")");
            }
            filter.append(")");
        } else if (search != null) {
            filter.append("(&(cn;lang-en=*" + search + "*)(uid=*))");
        }

        try {
            ctx = getLdapContext();
            results = ctx.search("", filter.toString(), ctrls);
            while (results.hasMore()) {
                SearchResult result = (SearchResult) results.next();
                // An alumn user
                if (result.getAttributes().get("uid") != null) {
                    UserData userData = createUserDataFromLdapData(result.getAttributes());
                    if (userData != null) {
                        userDataList.add(userData);
                    }
                }
            }
        } catch (NamingException e) {
            throw new CommonReportSet.UnknownErrorException(e, "Unable to list user data from LDAP.");
        } finally {
            try {
                if (results != null) {
                    results.close();
                }
                if (ctx != null) {
                    ctx.close();
                }
            }
            catch (Exception ignored) {
                // Ignore.
            }
        }
        return userDataList;
    }

    @Override
    protected Group onGetGroup(final String groupId) throws ControllerReportSet.GroupNotExistsException
    {
        throw new ControllerReportSet.GroupNotExistsException(groupId);
    }

    @Override
    public List<Group> onListGroups(Set<String> filterGroupIds, Set<Group.Type> filterGroupTypes)
    {
        return new LinkedList<Group>();
    }

    @Override
    public Set<String> onListGroupUserIds(final String groupId)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected Set<String> onListUserGroupIds(String userId)
    {
        return new HashSet<String>();
    }

    @Override
    public String onCreateGroup(final Group group)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void onModifyGroup(final Group group)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void onDeleteGroup(final String groupId)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void onAddGroupUser(final String groupId, final String userId)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void onRemoveGroupUser(final String groupId, final String userId)
    {
        throw new UnsupportedOperationException();
    }


    /**
     * Creates context with pooled connection for LDAP.
     *
     * @return {@link DirContext}
     */
    private DirContext getLdapContext() throws NamingException {
        // LDAP client initialization
        String ldapClientDn = configuration.getString(ControllerConfiguration.SECURITY_LDAP_BINDDN );
        String ldapClientSecret = configuration.getString(ControllerConfiguration.SECURITY_LDAP_CLIENT_SECRET);
        Hashtable<String,String> env = new Hashtable <String,String>();
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "ssl");
        env.put(Context.PROVIDER_URL, ldapAuthorizationServer);
        env.put(Context.SECURITY_PRINCIPAL, ldapClientDn);
        env.put(Context.SECURITY_CREDENTIALS, ldapClientSecret);
        return new InitialDirContext(env);
    }

    /**
     * Returns userData if parsing went well. If name is not set properly returns null.
     *
     * @return {@link UserData}
     */
    private UserData createUserDataFromLdapData(Attributes attributes) throws NamingException {

        // Required fields
        if (attributes.get("uid") == null) {
            throw new IllegalArgumentException("User data must contain uid.");
        }
        // Ignore if not set
        if (attributes.get("sn") == null || attributes.get("givenname") == null) {
            return null;
        }


        String userId = (String) attributes.get("uid").get();
        UserData userData = new UserData();
        UserInformation userInformation = userData.getUserInformation();
        userInformation.setUserId(userId);
        userInformation.setFirstName((String) attributes.get("givenName").get());
        userInformation.setLastName((String) attributes.get("sn").get());
        Set<String> principalNames = new HashSet<>();
        principalNames.add(userId + "@cuni.cz");
        userInformation.setPrincipalNames(principalNames);
/*        if (data.has("organization")) {
            TODO : set faculty?
            JsonNode organization = data.get("organization");
            if (!organization.isNull()) {
                userInformation.setOrganization(organization.getTextValue());
            }
        }*/
        if (attributes.get("mail") != null) {
            userInformation.setEmail((String) attributes.get("mail").get());
        }
        return userData;
    }

    /**
     * Perform given {@code httpRequest}.
     *
     * @param httpRequest    to be performed
     * @param description    for error reporting
     * @param requestHandler to handle response or error
     * @return result from given {@code requestHandler}
     */
    private <T> T performRequest(HttpRequestBase httpRequest, String description, RequestHandler<T> requestHandler)
    {
        try {
            httpRequest.addHeader("Authorization", requestAuthorizationHeader);
            httpRequest.setHeader("Accept", "application/hal+json");
            httpRequest.setHeader("Cache-Control", "no-cache");
            HttpResponse response = httpClient.execute(httpRequest);
            StatusLine statusLine = response.getStatusLine();
            int statusCode = statusLine.getStatusCode();
            if (statusCode == HttpStatus.SC_NO_CONTENT) {
                return null;
            }
            else if (statusCode >= HttpStatus.SC_OK && statusCode <= HttpStatus.SC_ACCEPTED) {
                JsonNode data = readJson(response.getEntity());
                if (data == null) {
                    data = jsonMapper.createObjectNode();
                }
                return requestHandler.success(data);
            }
            else {
                String content = readContent(response.getEntity());
                String detail = null;
                if (content != null && !content.isEmpty()) {
                    try {
                        JsonNode jsonNode = jsonMapper.readTree(content);
                        if (jsonNode.has("detail")) {
                            JsonNode detailNode = jsonNode.get("detail");
                            if (!detailNode.isNull()) {
                                detail = detailNode.asText();
                            }
                        }
                    }
                    catch (Exception exception) {
                        logger.warn("Cannot parse json: {}", content);
                        detail = content;
                    }
                }
                requestHandler.error(statusLine, (detail != null ? detail : ""));
                String error = description + ": " + statusLine.toString();
                if (detail != null) {
                    error += ": " + detail;
                }
                throw new CommonReportSet.UnknownErrorException(error);
            }
        }
        catch (ReportRuntimeException exception) {
            throw exception;
        }
        catch (Exception exception) {
            throw new CommonReportSet.UnknownErrorException(exception, description + ".");
        }
        finally {
            httpRequest.releaseConnection();
        }
    }

    /**
     * @param httpEntity to be read
     * @return {@link JsonNode} from given {@code httpEntity}
     */
    private JsonNode readJson(HttpEntity httpEntity)
    {
        if (httpEntity.getContentLength() == 0) {
            return null;
        }
        try {
            InputStream inputStream = httpEntity.getContent();
            try {
                int available = inputStream.available();
                return jsonMapper.readTree(inputStream);
            }
            finally {
                inputStream.close();
            }
        }
        catch (EOFException exception) {
            throw new RuntimeException("JSON is empty.", exception);
        }
        catch (IOException exception) {
            throw new RuntimeException("Reading JSON failed.", exception);
        }
    }

    /**
     * Read all content from given {@code httpEntity}.
     *
     * @param httpEntity to be read
     */
    private String readContent(HttpEntity httpEntity)
    {
        if (httpEntity != null) {
            try {
                return EntityUtils.toString(httpEntity);
            }
            catch (IOException exception) {
                throw new RuntimeException("Reading content failed.", exception);
            }
        }
        return null;
    }

    /**
     * @param httpResponse to be handled
     * @throws RuntimeException is always thrown
     */
    private <T> T handleAuthorizationRequestError(HttpResponse httpResponse)
    {
        JsonNode jsonNode = readJson(httpResponse.getEntity());
        return handleAuthorizationRequestError(jsonNode);
    }

    /**
     * @param jsonNode to be handled
     * @throws RuntimeException is always thrown
     */
    private <T> T handleAuthorizationRequestError(JsonNode jsonNode)
    {
        String title = "unknown";
        String detail = "none";
        if (jsonNode != null) {
            title = jsonNode.get("title").getTextValue();
            detail = jsonNode.get("detail").getTextValue();
        }
        throw new RuntimeException(String.format("Authorization request failed: %s, %s", title, detail));
    }

    /**
     * @param exception to be handled
     * @throws RuntimeException is always thrown
     */
    private <T> T handleAuthorizationRequestError(Exception exception)
    {
        throw new RuntimeException(String.format("Authorization request failed. %s", exception.getMessage()));
    }

    /**
     * @param data from authorization server
     * @return {@link UserData}
     */
    private static UserData createUserDataFromWebServiceData(JsonNode data)
    {
        // Required fields
        if (!data.has("principal_names")) {
            throw new IllegalArgumentException("User data must contain identifier.");
        }
        if (!data.has("first_name") || !data.has("last_name")) {
            throw new IllegalArgumentException("User data must contain given and family name.");
        }

        UserData userData = new UserData();

        String userId = null;
        JsonNode principalNames = data.get("principal_names");
        if (principalNames.isArray()){
            for (JsonNode principalNameNode : principalNames) {
                String principalName = principalNameNode.getTextValue();
                if (principalName.endsWith("@cuni.cz")) {
                    userId = principalName.replace("@cuni.cz", "");
                    break;
                } else {
                    // TODO: remove debug code folows
                    //userId = "91550799";
                    //throw new CommonReportSet.UnknownErrorException("Unable to parse cuniPersonalId from userData.");
                }
            }
        }

        // Common user data
        UserInformation userInformation = userData.getUserInformation();
        userInformation.setUserId(userId);
        userInformation.setFirstName(data.get("first_name").getTextValue());
        userInformation.setLastName(data.get("last_name").getTextValue());
        if (data.has("organization")) {
            JsonNode organization = data.get("organization");
            if (!organization.isNull()) {
                userInformation.setOrganization(organization.getTextValue());
            }
        }
        if (data.has("mail")) {
            JsonNode email = data.get("mail");
            if (!email.isNull()) {
                userInformation.setEmail(email.getTextValue());
            }
        }
        if (data.has("principal_names")) {
            Iterator<JsonNode> principalNameIterator = data.get("principal_names").getElements();
            while (principalNameIterator.hasNext()) {
                JsonNode principalName = principalNameIterator.next();
                userInformation.addPrincipalName(principalName.getTextValue());
            }
        }

        // Additional user data
        if (data.has("language")) {
            JsonNode language = data.get("language");
            if (!language.isNull()) {
                Locale locale = new Locale(language.getTextValue());
                userData.setLocale(locale);
            }
        }
        if (data.has("timezone")) {
            JsonNode timezone = data.get("timezone");
            if (!timezone.isNull()) {
                DateTimeZone timeZone = DateTimeZone.forID(timezone.getTextValue());
                userData.setTimeZone(timeZone);
            }
        }
        if (data.has("zoneinfo")) {
            JsonNode timezone = data.get("zoneinfo");
            if (!timezone.isNull()) {
                DateTimeZone timeZone = DateTimeZone.forID(timezone.getTextValue());
                userData.setTimeZone(timeZone);
            }
        }
        // for AuthN Server v0.6.4 and newer
        if (data.has("authn_provider") && data.has("authn_instant") && data.has("loa")) {
            userData.setUserAuthorizationData(new UserAuthorizationData(
                    data.get("authn_provider").getTextValue(),
                    DateTime.parse(data.get("authn_instant").getTextValue()),
                    data.get("loa").getIntValue()));
        }
        // for AuthN Server v0.6.3 and older
        if (data.has("authentication_info")) {
            JsonNode authenticationInfo = data.get("authentication_info");
            if (authenticationInfo.has("provider") && authenticationInfo.has("loa")) {
                userData.setUserAuthorizationData(new UserAuthorizationData(
                        authenticationInfo.get("provider").getTextValue(),
                        null,
                        authenticationInfo.get("loa").getIntValue()));
            }
        }

        return userData;
    }

    /**
     * @return new instance of {@link ServerAuthorization}
     * @throws IllegalStateException when other {@link Authorization} already exists
     */
    public static ServerAuthorization createInstance(ControllerConfiguration configuration,
                                                     EntityManagerFactory entityManagerFactory) throws IllegalStateException
    {
        ServerAuthorization serverAuthorization = new ServerAuthorization(configuration, entityManagerFactory);
        Authorization.setInstance(serverAuthorization);
        return serverAuthorization;
    }

    /**
     * @param fileName    where to write
     * @param accessToken to be written
     */
    private static void writeRootAccessToken(String fileName, String accessToken)
    {
        try {
            File file = new File(fileName);
            if (!file.exists()) {
                if (file.createNewFile()) {
                    chmod(fileName, 0600);
                }
            }
            BufferedWriter output = new BufferedWriter(new FileWriter(file));
            try {
                output.write(accessToken);
            }
            finally {
                output.close();
            }
        }
        catch (IOException exception) {
            logger.error("Cannot write root access token to file " + fileName, exception);
        }
    }

    /**
     * @param fileName
     * @param mode
     * @return result of chmod
     */
    private static int chmod(String fileName, int mode)
    {
        try {
            Class<?> fspClass = Class.forName("java.util.prefs.FileSystemPreferences");
            Method chmodMethod = fspClass.getDeclaredMethod("chmod", String.class, Integer.TYPE);
            chmodMethod.setAccessible(true);
            return (Integer) chmodMethod.invoke(null, fileName, mode);
        }
        catch (Throwable throwable) {
            logger.error("Cannot chmod file " + fileName + " to mode " + mode, throwable);
            return -1;
        }
    }

    /**
     * Http request handler for {@link #performRequest}
     */
    private static abstract class RequestHandler<T>
    {
        /**
         * Handle HTTP json response.
         *
         * @param data
         * @return parsed json response
         */
        public T success(JsonNode data)
        {
            return null;
        }

        /**
         * Handle HTTP error.
         *
         * @param statusLine
         * @param detail
         */
        public void error(StatusLine statusLine, String detail)
        {
        }
    }
}
