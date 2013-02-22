using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading.Tasks;
using System.Security.Claims;
using HawkNet.WebApi;

namespace HawkNet.Tests
{
    [TestClass]
    public class HawkMessageHandlerFixture
    {
        [TestMethod]
        public void ShouldSkipAuthOnWrongAuthScheme()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic");
            
            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.IsNotNull(response);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        [TestMethod]
        public void ShouldFailOnWMissingHostHeader()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage();
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"123\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.AreEqual("Missing Host header", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnMissingAuthAttribute()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Missing attributes", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnUnknownAuthAttribute()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"123\", ts = \"1353788437\", nonce = \"1353788437\", x = \"3\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Unknown attributes", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnInvalidAuthFormat()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.AreEqual("Invalid header format", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnCredentialsFuncException()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) => { throw new Exception("Invalid"); });
            var invoker = new HttpMessageInvoker(handler);

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Unknown user", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnMissingCredentials()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) => { return null; });
            var invoker = new HttpMessageInvoker(handler);

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Missing credentials", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnInvalidCredentials()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) => 
            {
                return new HawkCredential
                    {
                        Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                        User = "steve"
                    };
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Invalid credentials", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnUnknownCredentialsAlgorithm()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmac-sha-0",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Unknown algorithm", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldFailOnUnknownBadMac()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmacsha256",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Bad mac", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldReturnChallengeOnEmptyAuthHeader()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmac-sha-0",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
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

            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return credential;
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac));

            request.Headers.Host = "example.com";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(ClaimsPrincipal));
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

            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return credential;
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac));

            request.Headers.Host = "example.com";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(ClaimsPrincipal));
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

        class DummyHttpMessageHandler : HttpMessageHandler
        {
            protected override System.Threading.Tasks.Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(new HttpResponseMessage(HttpStatusCode.OK));

                return tsc.Task;
            }
        }

    }
}
