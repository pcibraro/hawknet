using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HawkNet.Tests
{
    [TestClass]
    public class HawkFixture
    {
        const string ValidAuthorization = "id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"lDdDLlWQhgcxTvYgzzLo3EZExog=\", ext=\"hello\"";

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnNullAuthorization()
        {
            Hawk.Authenticate(null, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnEmptyAuthorization()
        {
            Hawk.Authenticate(" ", "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnNullHost()
        {
            Hawk.Authenticate(ValidAuthorization, null, "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ShouldFailAuthenticationOnEmptyHost()
        {
            Hawk.Authenticate(ValidAuthorization, " ", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing credentials")]
        public void ShouldFailAuthenticationOnNullCredential()
        {
            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => null);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing attributes")]
        public void ShouldFailAuthenticationOnMissingAuthAttribute()
        {
            Hawk.Authenticate("ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"",
                "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing attributes")]
        public void ShouldFailAuthenticationOnUnknownAuthAttribute()
        {
            Hawk.Authenticate("id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", x=\"3\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"",
                "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Invalid credentials")]
        public void ShouldFailAuthenticationOnMissingCredentialAlgorithm()
        {
            var credential = new HawkCredential
            {
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Invalid credentials")]
        public void ShouldFailAuthenticationOnMissingCredentialKey()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                User = "steve"
            };

            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Unknown algorithm")]
        public void ShouldFailAuthenticationOnUnknownCredentialAlgorithm()
        {
            var credential = new HawkCredential
            {
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "foo",
                User = "steve"
            };

            Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Bad mac")]
        public void ShouldFailAuthenticationOnInvalidMac()
        {
            var authorization = "id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"lDdDLlWQhgcxTvYgzzLo3EZExogXXXX=\", ext=\"hello\"";
            Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha1()
        {
            var credential = new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmacsha1",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential);

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            var principal = Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);

            Assert.IsNotNull(principal);
            Assert.IsInstanceOfType(principal, typeof(ClaimsPrincipal));
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha256()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential);

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);
            
            var principal = Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);

            Assert.IsNotNull(principal);
            Assert.IsInstanceOfType(principal, typeof(ClaimsPrincipal));
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithPayloadHashAndSha256()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

            var payload = Encoding.UTF8.GetBytes("Thank you for flying Hawk");
            var hash = Convert.ToBase64String(hmac.ComputeHash(payload));
            
            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, hash);

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\", hash=\"{2}\"",
                ts, mac, hash);

            var principal = Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential, 
                requestPayload:new Lazy<byte[]>(() => payload));

            Assert.IsNotNull(principal);
            Assert.IsInstanceOfType(principal, typeof(ClaimsPrincipal));
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void ShouldFailWithTimestampInThePast()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now.Subtract(TimeSpan.FromDays(1))) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential);

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void ShouldFailWithTimestampInTheFuture()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now.Add(TimeSpan.FromDays(1))) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential);

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => credential);
        }

        [TestMethod]
        public void ShouldCalculateMac()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac("example.com", "Get", 
                new Uri("http://example.com:8080/resource/4?filter=a"), "hello", "1353788437", Hawk.GetRandomString(6), credential);

            Assert.AreEqual("zsj33M9aSXrxqlD1qs1haK/IBoQ=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithPayloadHash()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

            var hash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes("Thank you for flying Hawk")));

            var mac = Hawk.CalculateMac("example.com", "Get",
                new Uri("http://example.com:8080/resource/4?filter=a"), "hello", "1353788437", Hawk.GetRandomString(6), credential, hash);

            Assert.AreEqual("zsDVOQK4cEPBaj6VOuGQF4nh30w=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithMissingExt()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac("example.com", "Get", new Uri("http://example.com:8080/resource/4?filter=a"),
                null, "1353788437", Hawk.GetRandomString(6), credential);

            Assert.AreEqual("njcQeYbHor0gwJGoH3+ktSQ7nqs=", mac);
        }

        private HawkCredential GetCredential(string id)
        {
            return new HawkCredential
            {
                Id = id,
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = (id == "1" ? "hmacsha1" : "hmacsha256"),
                User = "steve"
            };
        }
    }
}
