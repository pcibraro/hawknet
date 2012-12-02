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

namespace HawkNet.Tests
{
    [TestClass]
    public class HawkMessageHandlerFixture
    {
        [TestMethod]
        public void ShouldFailOnMissingAuthHeader()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");

            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Missing Authorization header", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
        }

        [TestMethod]
        public void ShouldFailOnWrongAuthScheme()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), GetCredential);
            var invoker = new HttpMessageInvoker(handler);

            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic");
            
            var response = invoker.SendAsync(request, new CancellationToken())
                .Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.AreEqual("Incorrect scheme", response.ReasonPhrase);
            Assert.IsTrue(response.Headers.WwwAuthenticate.Any(h => h.Scheme == "Hawk"));
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
                return new HawkMessageHandler.HawkCredential
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
                return new HawkMessageHandler.HawkCredential
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
                return new HawkMessageHandler.HawkCredential
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
        public void ShouldCalculateMac()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "example.com";

            var attributes = new NameValueCollection() { 
                { "ts", "1353788437" },
                { "ext", "hello"}
            };
            var credential = new HawkMessageHandler.HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = HawkMessageHandler.CalculateMac(request, attributes, credential);

            Assert.AreEqual("lDdDLlWQhgcxTvYgzzLo3EZExog=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithMissingExt()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com:8080/resource/4?filter=a");
            request.Headers.Host = "example.com";

            var attributes = new NameValueCollection() { 
                { "ts", "1353788437" }
            };
            var credential = new HawkMessageHandler.HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = HawkMessageHandler.CalculateMac(request, attributes, credential);

            Assert.AreEqual("utHS0Jh4n7lwORuDl2Ht3MKHZPU=", mac);
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha1()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return new HawkMessageHandler.HawkCredential
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
            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(HawkMessageHandler.HawkPrincipal));
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderWithSha256()
        {
            var handler = new HawkMessageHandler(new DummyHttpMessageHandler(), (id) =>
            {
                return new HawkMessageHandler.HawkCredential
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
            Assert.AreEqual(Thread.CurrentPrincipal.GetType(), typeof(HawkMessageHandler.HawkPrincipal));
        }

        private HawkMessageHandler.HawkCredential GetCredential(string id)
        {
            return new HawkMessageHandler.HawkCredential
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
