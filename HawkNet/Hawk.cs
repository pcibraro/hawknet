using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

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

        static Hawk()
        {
            SupportedAttributes = RequiredAttributes.Concat(OptionalAttributes).ToArray();
        }

        /// <summary>
        /// Authenticates an upcoming request message
        /// </summary>
        /// <param name="request">Http request instance</param>
        /// <param name="credentials">A method for searching across the available credentials</param>
        /// <param name="timestampSkewSec">Time skew in seconds for timestamp verification</param>
        /// <returns>A new ClaimsPrincipal instance representing the authenticated user</returns>
        public static ClaimsPrincipal Authenticate(HttpRequestMessage request, Func<string, HawkCredential> credentials, int timestampSkewSec = 60)
        {
            var requestPayload = new Lazy<byte[]>(() =>
            {
                var task = request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var payload = task.GetAwaiter().GetResult();

                return payload;
            });

            return Authenticate(request.Headers.Authorization.Parameter,
                request.Headers.Host,
                request.Method.ToString(),
                request.RequestUri,
                credentials,
                timestampSkewSec,
                requestPayload);
        }

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
        public static ClaimsPrincipal Authenticate(string authorization, string host, string method, Uri uri, Func<string, HawkCredential> credentials, int timestampSkewSec = 60, Lazy<byte[]> requestPayload = null)
        {
            if (string.IsNullOrWhiteSpace(authorization))
            {
                throw new ArgumentException("Authorization parameter can not be null or empty", "authorization");
            }

            if (string.IsNullOrWhiteSpace(host))
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

            if (string.IsNullOrWhiteSpace(credential.Algorithm) ||
                string.IsNullOrWhiteSpace(credential.Key))
            {
                throw new SecurityException("Invalid credentials");
            }

            if (!SupportedAlgorithms.Any(a => string.Equals(a, credential.Algorithm, StringComparison.InvariantCultureIgnoreCase)))
            {
                throw new SecurityException("Unknown algorithm");
            }

            if (!string.IsNullOrWhiteSpace(attributes["hash"]))
            {
                var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
                hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

                var hash = Convert.ToBase64String(hmac.ComputeHash(requestPayload.Value));

                if (attributes["hash"] != hash)
                {
                    throw new SecurityException("Bad payload hash");
                }
            }

            var mac = CalculateMac(host, method, uri, attributes["ext"], attributes["ts"], attributes["nonce"], credential, attributes["hash"]);
            if (!mac.Equals(attributes["mac"]))
            {
                throw new SecurityException("Bad mac");
            }

            var userClaim = new Claim(ClaimTypes.Name, (credential.User != null) ? credential.User : "");
            var allClaims = Enumerable.Concat(new Claim[] { userClaim }, 
                (credential.AdditionalClaims != null) ? credential.AdditionalClaims : Enumerable.Empty<Claim>());

            var identity = new ClaimsIdentity(allClaims, "Hawk");
            var principal = new ClaimsPrincipal(new ClaimsIdentity[] { identity });

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
            if(string.IsNullOrWhiteSpace(host))
                throw new ArgumentException("The host can not be null or empty", "host");

            if (string.IsNullOrWhiteSpace(method))
                throw new ArgumentException("The method can not be null or empty", "method");

            if(credential == null)
                throw new ArgumentNullException("The credential can not be null", "credential");

            if (string.IsNullOrWhiteSpace(nonce))
            {
                nonce = GetRandomString(6);
            }

            var normalizedTs = ConvertToUnixTimestamp((ts.HasValue) ? ts.Value : DateTime.UtcNow).ToString();

            var mac = CalculateMac(host, method, uri, ext, normalizedTs, nonce, credential, payloadHash);

            var authorization = string.Format("id=\"{0}\", ts=\"{1}\", nonce=\"{2}\", mac=\"{3}\", ext=\"{4}\"",
                    credential.Id, ts, nonce, mac, ext);

            if (!string.IsNullOrWhiteSpace(payloadHash))
            {
                authorization += string.Format("hash=\"{0}\"", payloadHash);
            }

            return authorization;
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
        public static string CalculateMac(string host, string method, Uri uri, string ext, string ts, string nonce, HawkCredential credential, string payloadHash = null)
        {
            var hmac = HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

            var sanitizedHost = (host.IndexOf(':') > 0) ?
                host.Substring(0, host.IndexOf(':')) :
                host;

            var normalized = "hawk.1.header\n" + 
                        ts + "\n" +
                        nonce + "\n" + 
                        method.ToUpper() + "\n" +
                        uri.PathAndQuery + "\n" +
                        host.ToLower() + "\n" +
                        uri.Port.ToString() + "\n" +
                        ((!string.IsNullOrWhiteSpace(payloadHash)) ? payloadHash + "\n" : "") + 
                        ((!string.IsNullOrWhiteSpace(ext)) ? ext : "") + "\n";

            var messageBytes = Encoding.ASCII.GetBytes(normalized);

            var mac = hmac.ComputeHash(messageBytes);

            return Convert.ToBase64String(mac);
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
    }
}
