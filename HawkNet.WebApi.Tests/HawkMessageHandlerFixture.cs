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
        public void ShouldSkipAuthOnMissingAuthHeader()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.IsNotNull(response);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

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

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Missing Host header", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
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
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
        }

        [TestMethod]
        public void ShouldFailOnUnknownAuthAttribute()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"123\", ts = \"1353788437\", x = \"3\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Unknown attributes", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
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

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Invalid header format", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
        }

        [TestMethod]
        public void ShouldFailOnCredentialsFuncException()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) => { throw new Exception("Invalid"); });
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Unknown user", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
        }

        [TestMethod]
        public void ShouldFailOnMissingCredentials()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) => { return null; });
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Missing credentials", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
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

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Invalid credentials", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
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

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Unknown algorithm", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
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

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
            request.Headers.Host = "localhost";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Bad mac", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha1()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmacsha1",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };
            });

            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"1353788437\", mac = \"lDdDLlWQhgcxTvYgzzLo3EZExog=\", ext = \"hello\"");
            request.Headers.Host = "example.com";

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(ClaimsPrincipal));
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha256()
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

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Hawk", "id = \"456\", ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\"");
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
