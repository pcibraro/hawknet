using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Web;
using System.Diagnostics;

#if NET45
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
#endif

namespace HawkNet
{
    /// <summary>
    /// Hawk main class. It provides methods for generating a Hawk authorization header on the client side and authenticate it on the
    /// service side.
    /// </summary>
    public static class Hawk
    {
        readonly static string[] RequiredAttributes = { "id", "ts", "mac", "nonce" };
        readonly static string[] OptionalAttributes = { "ext", "hash" };
        readonly static string[] SupportedAttributes;
        readonly static string[] SupportedAlgorithms = { "HMACSHA1", "HMACSHA256" };
        readonly static string RandomSource = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        static TraceSource TraceSource = new TraceSource("HawkNet");

        static Hawk()
        {
            SupportedAttributes = RequiredAttributes.Concat(OptionalAttributes).ToArray();
        }

#if NET45
        /// <summary>
        /// Authenticates an upcoming request message
        /// </summary>
        /// <param name="request">Http request instance</param>
        /// <param name="credentials">A method for searching across the available credentials</param>
        /// <param name="timestampSkewSec">Time skew in seconds for timestamp verification</param>
        /// <returns>A new ClaimsPrincipal instance representing the authenticated user</returns>
        public static IPrincipal Authenticate(HttpRequestMessage request, Func<string, HawkCredential> credentials, int timestampSkewSec = 60)
        {
            if (request.Method == HttpMethod.Get &&
                !string.IsNullOrEmpty(request.RequestUri.Query))
            {
                var query = HttpUtility.ParseQueryString(request.RequestUri.Query);
                if(query["bewit"] != null)
                {
                    return AuthenticateBewit(query["bewit"],
                        request.Headers.Host,
                        request.RequestUri,
                        credentials);
                }
            }
            
            Func<byte[]> requestPayload = () =>
            {
                var task = request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var payload = task.GetAwaiter().GetResult();

                return payload;
            };

            return Authenticate(request.Headers.Authorization.Parameter,
                request.Headers.Host,
                request.Method.ToString(),
                request.RequestUri,
                credentials,
                timestampSkewSec,
                requestPayload);
        }
#endif

        /// <summary>
        /// Authenticates an upcoming request message
        /// </summary>
        /// <param name="authorization">Authorization header</param>
        /// <param name="host">Host header</param>
        /// <param name="method">Request method</param>
        /// <param name="uri">Request Uri</param>
        /// <param name="credentials">A method for searching across the available credentials</param>
        /// <param name="timestampSkewSec">Accepted Time skew for timestamp verification</param>
        /// <param name="payloadHash">Hash of the request payload</param>
        /// <returns></returns>
        public static IPrincipal Authenticate(string authorization, string host, string method, Uri uri, Func<string, HawkCredential> credentials, int timestampSkewSec = 60, Func<byte[]> requestPayload = null)
        {
            TraceSource.TraceInformation(string.Format("Received Auth header: {0}",
                authorization));
            
            if (string.IsNullOrEmpty(authorization))
            {
                throw new ArgumentException("Authorization parameter can not be null or empty", "authorization");
            }

            if (string.IsNullOrEmpty(host))
            {
                throw new ArgumentException("Host header can not be null or empty", "host");
            }

            var attributes = ParseAttributes(authorization);

            if (!RequiredAttributes.All(a => attributes.AllKeys.Any(k => k == a)))
            {
                throw new SecurityException("Missing attributes");
            }

            if (!attributes.AllKeys.All(a => SupportedAttributes.Any(k => k == a)))
            {
                throw new SecurityException( "Unknown attributes");
            }

            // Check timestamp staleness
            if (!CheckTimestamp(attributes["ts"], timestampSkewSec))
            {
                throw new SecurityException("Stale or missing timestamp");
            }

            HawkCredential credential = null;
            try
            {
                credential = credentials(attributes["id"]);
            }
            catch (Exception ex)
            {
                throw new SecurityException("Unknown user", ex);
            }

            if (credential == null)
            {
                throw new SecurityException("Missing credentials");
            }

            if (string.IsNullOrEmpty(credential.Algorithm) ||
                string.IsNullOrEmpty(credential.Key))
            {
                throw new SecurityException("Invalid credentials");
            }

            if (!SupportedAlgorithms.Any(a => 
                string.Equals(a, credential.Algorithm, StringComparison.InvariantCultureIgnoreCase)))
            {
                throw new SecurityException("Unknown algorithm");
            }

            if (!string.IsNullOrEmpty(attributes["hash"]))
            {
                var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
                
                hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

                var hash = Convert.ToBase64String(hmac.ComputeHash(requestPayload()));

                if (attributes["hash"] != hash)
                {
                    throw new SecurityException("Bad payload hash");
                }
            }

            var mac = CalculateMac(host, 
                method, 
                uri, 
                attributes["ext"], 
                attributes["ts"], 
                attributes["nonce"], 
                credential, "header", 
                attributes["hash"]);

            if (!mac.Equals(attributes["mac"]))
            {
                throw new SecurityException("Bad mac");
            }

#if NET45
            var userClaim = new Claim(ClaimTypes.Name, credential.User);
            var allClaims = Enumerable.Concat(new Claim[] { userClaim }, 
                (credential.AdditionalClaims != null) ? credential.AdditionalClaims : Enumerable.Empty<Claim>());

            var identity = new ClaimsIdentity(allClaims, "Hawk");
            var principal = new ClaimsPrincipal(new ClaimsIdentity[] { identity });
#else
            var identity = new GenericIdentity(credential.User, "Hawk");
            var principal = new GenericPrincipal(identity, credential.Roles);
#endif
            return principal;
        }

        /// <summary>
        /// Creates a new Hawk Authorization header based on the provided parameters
        /// </summary>
        /// <param name="host">Host header</param>
        /// <param name="method">Request method</param>
        /// <param name="uri">Request uri</param>
        /// <param name="credential">Credential used to calculate the MAC</param>
        /// <param name="ext">Optional extension attribute</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="nonce">Random Nonce</param>
        /// <param name="payloadHash">Hash of the request payload</param>
        /// <returns>Hawk authorization header</returns>
        public static string GetAuthorizationHeader(string host, string method, Uri uri, HawkCredential credential, string ext = null, DateTime? ts = null, string nonce = null, string payloadHash = null)
        {
            if(string.IsNullOrEmpty(host))
                throw new ArgumentException("The host can not be null or empty", "host");

            if (string.IsNullOrEmpty(method))
                throw new ArgumentException("The method can not be null or empty", "method");

            if(credential == null)
                throw new ArgumentNullException("The credential can not be null", "credential");

            if (string.IsNullOrEmpty(nonce))
            {
                nonce = GetRandomString(6);
            }

            var normalizedTs = (ConvertToUnixTimestamp((ts.HasValue) 
                ? ts.Value : DateTime.UtcNow) / 1000).ToString();

            var mac = CalculateMac(host, 
                method, 
                uri, 
                ext, 
                normalizedTs, 
                nonce, 
                credential, 
                "header", 
                payloadHash);

            var authorization = string.Format("id=\"{0}\", ts=\"{1}\", nonce=\"{2}\", mac=\"{3}\", ext=\"{4}\"",
                    credential.Id, normalizedTs, nonce, mac, ext);

            if (!string.IsNullOrEmpty(payloadHash))
            {
                authorization += string.Format(", hash=\"{0}\"", payloadHash);
            }

            return authorization;
        }

        /// <summary>
        /// Gets a new Bewit for Single URI authorization 
        /// </summary>
        /// <param name="host">Host name</param>
        /// <param name="uri">Request uri</param>
        /// <param name="credential">Hawk credential</param>
        /// <param name="ttlSec">Time to live in seconds for the Bewit</param>
        /// <param name="ext">Extension attributes</param>
        /// <returns>A fresh Bewit</returns>
        public static string GetBewit(string host, Uri uri, HawkCredential credential, int ttlSec, string ext = null)
        {
            var now = ConvertToUnixTimestamp(DateTime.Now);

            var expiration = Math.Floor(now / 1000) + ttlSec;

            var mac = CalculateMac(host, "GET", uri, ext, expiration.ToString(), "", credential, "bewit");

            var bewit = Convert.ToBase64String(
                Encoding.UTF8.GetBytes(credential.Id + '\\' + expiration + '\\' + mac + '\\' + ext));

            return bewit;
        }

        public static IPrincipal AuthenticateBewit(string bewit, string host, Uri uri, Func<string, HawkCredential> credentials, int timestampSkewSec = 60)
        {
            var decodedBewit = Encoding.UTF8.GetString(Convert.FromBase64String(bewit));

            var bewitParts = decodedBewit.Split('\\');
            if (bewitParts.Length != 4) 
            {
                throw new SecurityException("Invalid bewit structure");
            }

            double expiration;
            if(!double.TryParse(bewitParts[1], out expiration))
            {
                throw new SecurityException("Invalid expiration in bewit structure");
            }

            var now = ConvertToUnixTimestamp(DateTime.Now);

            if (expiration * 1000 <= now) 
            {
                throw new SecurityException("Access expired");
            }

            HawkCredential credential = null;
            try
            {
                credential = credentials(bewitParts[0]);
            }
            catch (Exception ex)
            {
                throw new SecurityException("Unknown user", ex);
            }

            if (credential == null)
            {
                throw new SecurityException("Missing credentials");
            }

            if (string.IsNullOrEmpty(credential.Algorithm) ||
                string.IsNullOrEmpty(credential.Key))
            {
                throw new SecurityException("Invalid credentials");
            }

            if (!SupportedAlgorithms.Any(a => string.Equals(a, credential.Algorithm, StringComparison.InvariantCultureIgnoreCase)))
            {
                throw new SecurityException("Unknown algorithm");
            }

            var mac = CalculateMac(uri.Host, "GET", RemoveBewitFromQuery(uri), 
                bewitParts[3], bewitParts[1], "", credential, "bewit");

            if (!mac.Equals(bewitParts[2]))
            {
                throw new SecurityException("Bad mac");
            }

#if NET45
            var userClaim = new Claim(ClaimTypes.Name, credential.User);
            var allClaims = Enumerable.Concat(new Claim[] { userClaim },
                (credential.AdditionalClaims != null) ? credential.AdditionalClaims : Enumerable.Empty<Claim>());

            var identity = new ClaimsIdentity(allClaims, "Hawk");
            var principal = new ClaimsPrincipal(new ClaimsIdentity[] { identity });
#else
            var identity = new GenericIdentity(credential.User, "Hawk");
            var principal = new GenericPrincipal(identity, credential.Roles);
#endif
            return principal;
        }

        /// <summary>
        /// Gets a random string of a given size
        /// </summary>
        /// <param name="size">Expected size for the generated string</param>
        /// <returns>Random string</returns>
        public static string GetRandomString(int size)
        {
            var result = new StringBuilder();
            var random = new Random(RandomSource.Length); 
            
            for (var i = 0; i < size; ++i) 
            {
                result.Append(RandomSource[random.Next(RandomSource.Length)]);
            }

            return result.ToString();
        }

        /// <summary>
        /// Parse all the attributes present in the Hawk authorization header
        /// </summary>
        /// <param name="authorization">Authorization header</param>
        /// <returns>List of parsed attributes</returns>
        public static NameValueCollection ParseAttributes(string authorization)
        {
            var allAttributes = new NameValueCollection();

            foreach (var attribute in authorization.Split(','))
            {
                var index = attribute.IndexOf('=');
                if (index > 0)
                {
                    var key = attribute.Substring(0, index).Trim();
                    var value = attribute.Substring(index + 1).Trim();

                    if (value.StartsWith("\""))
                        value = value.Substring(1, value.Length - 2);

                    allAttributes.Add(key, value);
                }
            }

            return allAttributes;
        }

        /// <summary>
        /// Computes a mac following the Hawk rules
        /// </summary>
        /// <param name="host">Host header</param>
        /// <param name="method">Request method</param>
        /// <param name="uri">Request uri</param>
        /// <param name="ext">Extesion attribute</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="nonce">Nonce</param>
        /// <param name="credential">Credential</param>
        /// <param name="payload">Hash of the request payload</param>
        /// <returns>Generated mac</returns>
        public static string CalculateMac(string host, string method, Uri uri, string ext, string ts, string nonce, HawkCredential credential, string type, string payloadHash = null)
        {
            var hmac = HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

            var sanitizedHost = (host.IndexOf(':') > 0) ?
                host.Substring(0, host.IndexOf(':')) :
                host;

            var normalized = "hawk.1." + type + "\n" + 
                        ts + "\n" +
                        nonce + "\n" + 
                        method.ToUpper() + "\n" +
                        uri.PathAndQuery + "\n" +
                        host.ToLower() + "\n" +
                        uri.Port.ToString() + "\n" +
                        ((!string.IsNullOrEmpty(payloadHash)) ? payloadHash + "\n" : "") + 
                        ((!string.IsNullOrEmpty(ext)) ? ext : "") + "\n";

            TraceSource.TraceInformation(string.Format("Normalized String: {0}",
                normalized));

            var messageBytes = Encoding.ASCII.GetBytes(normalized);

            var mac = hmac.ComputeHash(messageBytes);

            var encodedMac = Convert.ToBase64String(mac);

            TraceSource.TraceInformation(string.Format("Calculated mac: {0}",
                encodedMac));

            return encodedMac;
        }

        /// <summary>
        /// Converts a Datatime to an equivalent Unix Timestamp
        /// </summary>
        /// <param name="date"></param>
        /// <returns></returns>
        public static double ConvertToUnixTimestamp(DateTime date)
        {
            var origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            var diff = date.ToUniversalTime() - origin;
            return Math.Floor(diff.TotalSeconds);
        }

        private static bool CheckTimestamp(string ts, int timestampSkewSec)
        {
            double parsedTs;
            if(double.TryParse(ts, out parsedTs))
            {
                var now = ConvertToUnixTimestamp(DateTime.Now);

                // Check timestamp staleness
                if (Math.Abs((parsedTs * 1000) - now) > (timestampSkewSec * 1000))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            
            return false;
            
        }

        private static Uri RemoveBewitFromQuery(Uri uri)
        {
            var parsedQueryString = HttpUtility.ParseQueryString(uri.Query);
            parsedQueryString.Remove("bewit");

            var resultingQuery = string.Join("&", parsedQueryString.Cast<string>().Select(e => e + "=" + parsedQueryString[e]).ToArray());

            var newUri = string.Format("{0}://{1}:{2}{3}",
                uri.Scheme,
                uri.Host,
                uri.Port,
                uri.AbsolutePath);

            if (!string.IsNullOrEmpty(resultingQuery))
            {
                newUri += "?" + resultingQuery;
            }

            return new Uri(newUri);
        }
    }
}
