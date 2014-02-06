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

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\"");
            request.Headers.Host = "localhost";
            request.Content = new StringContent("foo");
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");

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

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

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
                return Task.FromResult(new HawkCredential
                    {
                        Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                        User = "steve"
                    });
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

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
                return Task.FromResult(new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmac-sha-0",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                });
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

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
                return Task.FromResult(new HawkCredential
                {
                    Id = "123",
                    Algorithm = "sha256",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                });
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Bad mac", response.ReasonPhrase);
        }

        [TestMethod]
        public void ShouldNotReturnChallengeOnEmptyAuthHeaderWithStatusOk()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return Task.FromResult(new HawkCredential
                {
                    Id = "123",
                    Algorithm = "sha1",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                });
            });

            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsFalse(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
        }

        [TestMethod]
        public void ShouldReturnChallengeOnEmptyAuthHeaderWithStatusUnauthorized()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(HttpStatusCode.Unauthorized), (id) =>
            {
                return Task.FromResult(new HawkCredential
                {
                    Id = "123",
                    Algorithm = "sha1",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                });
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
                    Algorithm = "sha1",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };

            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return Task.FromResult(credential);
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now);
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
                    Algorithm = "sha256",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };

            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return Task.FromResult(credential);
            });

            var invoker = new HttpMessageInvoker(handler);

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();
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
        public void ShouldGenerateServerAuthHeader()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return Task.FromResult(credential);
            }, 60, true);

            var invoker = new HttpMessageInvoker(handler);

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac));

            request.Headers.Host = "example.com";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsTrue(response.Headers.Any(h => h.Key == "Server-Authorization"));
            
        }

        private Task<HawkCredential> GetCredential(string id)
        {
            return Task.FromResult(new HawkCredential
            {
                Id = id,
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = (id == "1" ? "sha1" : "sha256"),
                User = "steve"
            });
        }

        class DummyHttpMessageHandler : HttpMessageHandler
        {
            HttpStatusCode statusCode;

            public DummyHttpMessageHandler(HttpStatusCode code = HttpStatusCode.OK)
            {
                this.statusCode = code;
            }

            protected override System.Threading.Tasks.Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent("foo");

                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);

                return tsc.Task;
            }
        }

    }
}
