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
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Hosting.Builder;
using Microsoft.Owin.Infrastructure;
using System.Text;
using System.IO;

namespace HawkNet.Owin.Tests
{
    [TestClass]
    public class HawkMiddlewareFixture
    {
        private IList<Tuple<Action<object>, object>> OnSendingHeadersActions = new List<Tuple<Action<object>, object>>();

        [TestMethod]
        public void ShouldSkipAuthOnWrongAuthScheme()
        {
            var builder = new AppBuilderFactory().Create();

            var context = new OwinContext();
            OwinRequest request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Basic " });

            var response = context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                new AppFuncTransition((env) => 
                    {
                        response.StatusCode = 200;
                        return Task.FromResult<object>(null);
                    }), 
                builder, 
                new HawkAuthenticationOptions
                {
                    Credentials = GetCredential
                }
            );

            middleware.Invoke(context);

            Assert.IsNotNull(response);
            Assert.AreEqual(200, response.StatusCode);
        }

        [TestMethod]
        public void ShouldFailOnMissingAuthAttribute()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));
            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                "ts = \"1353788437\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\""});

            var response = (OwinResponse)context.Response;
            response.StatusCode = 401;

            var middleware = new HawkAuthenticationMiddleware(
                new AppFuncTransition((env) => 
                    {
                        response.StatusCode = 401;
                        return Task.FromResult<object>(null);
                    }),
                builder,
                new HawkAuthenticationOptions
                {
                    Credentials = GetCredential
                }
            );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Missing attributes", logger.Messages[0]);
        }

        [TestMethod]
        public void ShouldFailOnUnknownAuthAttribute()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                "id = \"123\", ts = \"1353788437\", nonce = \"1353788437\", x = \"3\", mac = \"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\""});

            var response = (OwinResponse) context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                 new AppFuncTransition((env) =>
                 {
                     response.StatusCode = 401;
                     return Task.FromResult<object>(null);
                 }),
                builder,
                new HawkAuthenticationOptions
                {
                    Credentials = GetCredential
                }
            );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Unknown attributes", logger.Messages[0]);
        }

        [TestMethod]
        public void ShouldFailOnInvalidAuthFormat()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                ""});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                new AppFuncTransition((env) =>
                {
                    response.StatusCode = 401;
                    return Task.FromResult<object>(null);
                }),
               builder,
               new HawkAuthenticationOptions
               {
                   Credentials = GetCredential
               }
            );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Invalid header format", logger.Messages[0]);
        }

        [TestMethod]
        public void ShouldFailOnCredentialsFuncException()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "localhost" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\""});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                new AppFuncTransition((env) =>
                {
                    response.StatusCode = 401;
                    return Task.FromResult<object>(null);
                }),
               builder,
               new HawkAuthenticationOptions
               {
                   Credentials = (id) => { throw new Exception("Invalid"); }
               }
            );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Unknown user", logger.Messages[0]);
            
        }

        [TestMethod]
        public void ShouldFailOnMissingCredentials()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "localhost" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\""});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 401;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => { return null; }
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Unknown user", logger.Messages[0]);
        }

        [TestMethod]
        public void ShouldFailOnInvalidCredentials()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "localhost" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\""});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 401;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) =>
                               {
                                   return Task.FromResult(new HawkCredential
                                   {
                                       Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                                       User = "steve"
                                   });
                               }
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Invalid credentials", logger.Messages[0]);
        }

        [TestMethod]
        public void ShouldFailOnUnknownCredentialsAlgorithm()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "localhost" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"qrP6b5tiS2CO330rpjUEym/USBM=\", ext = \"hello\""});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 401;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) =>
                               {
                                   return Task.FromResult(new HawkCredential
                                   {
                                       Id = "123",
                                       Algorithm = "hmac-sha-0",
                                       Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                                       User = "steve"
                                   });
                               }
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Unknown algorithm", logger.Messages[0]);
        }

        [TestMethod]
        public void ShouldFailOnUnknownBadMac()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "localhost" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                "id = \"456\", ts = \"" + ts + "\", nonce=\"k3j4h2\", mac = \"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext = \"hello\""});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 401;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) =>
                               {
                                   return Task.FromResult(new HawkCredential
                                   {
                                       Id = "123",
                                       Algorithm = "sha256",
                                       Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                                       User = "steve"
                                   });
                               }
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.AreEqual("Bad mac", logger.Messages[0]);
        }

        [TestMethod]
        public void ShouldNotReturnChallengeOnEmptyAuthHeaderWithStatusOk()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "localhost" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) =>
                               {
                                   return Task.FromResult(new HawkCredential
                                   {
                                       Id = "123",
                                       Algorithm = "hmac-sha-0",
                                       Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                                       User = "steve"
                                   });
                               }
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.AreEqual(0, ((IDictionary<string, string[]>)response.Environment["owin.ResponseHeaders"]).Count);
        }

        [TestMethod]
        public void ShouldReturnChallengeOnEmptyAuthHeaderWithStatusUnauthorized()
        {
            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now).ToString();

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "localhost" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 401;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) =>
                               {
                                   return Task.FromResult(new HawkCredential
                                   {
                                       Id = "123",
                                       Algorithm = "hmac-sha-0",
                                       Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                                       User = "steve"
                                   });
                               }
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(401, response.StatusCode);
            Assert.IsNotNull(((IDictionary<string, string[]>)response.Environment["owin.ResponseHeaders"])["WWW-Authenticate"]);
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

            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "example.com" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac)});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => Task.FromResult(credential)
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.IsTrue(logger.Messages.Count == 0);
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

            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "example.com" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac)});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => Task.FromResult(credential)
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.IsTrue(logger.Messages.Count == 0);
        }

        [TestMethod]
        public void ShouldParseValidAuthHeaderAndPayloadWithSha256()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var body = "hello world";
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var ms = new MemoryStream();
            ms.Write(bodyBytes, 0, bodyBytes.Length);
            ms.Flush();
            ms.Seek(0, SeekOrigin.Begin);

            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var hash = Hawk.CalculatePayloadHash(body, "text/plain", credential);
            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now);
            var mac = Hawk.CalculateMac("example.com", "post", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header", hash);

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "post";
            request.Body = ms;
            request.SetHeader("Host", new string[] { "example.com" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.ContentType = "text/plain";
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\", hash=\"{2}\"",
                ts, mac, hash)});

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => Task.FromResult(credential)
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.IsTrue(logger.Messages.Count == 0);
        }

        [TestMethod]
        public void ShouldNotThrowWhenIncludeServerAuthorizationIsTrueAndAuthorizationIsMissing()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var body = "hello world";
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var ms = new MemoryStream();
            ms.Write(bodyBytes, 0, bodyBytes.Length);
            ms.Flush();
            ms.Seek(0, SeekOrigin.Begin);

            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));
            var context = new OwinContext();
            var request = (OwinRequest)context.Request;

            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "post";
            request.Body = ms;
            request.SetHeader("Host", new string[] { "example.com" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.ContentType = "text/plain";

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => Task.FromResult(credential),
                               IncludeServerAuthorization = true
                           }
                        );

            var task = middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.AreEqual(null, task.Exception);
        }

        [TestMethod]
        public void ShouldNotThrowWhenIncludeServerAuthorizationIsTrueAndAuthorizationIsOtherScheme()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var body = "hello world";
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var ms = new MemoryStream();
            ms.Write(bodyBytes, 0, bodyBytes.Length);
            ms.Flush();
            ms.Seek(0, SeekOrigin.Begin);

            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));
            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.SetHeader("Authorization", new[] { "OtherScheme" });

            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "post";
            request.Body = ms;
            request.SetHeader("Host", new string[] { "example.com" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.ContentType = "text/plain";

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => Task.FromResult(credential),
                               IncludeServerAuthorization = true
                           }
                        );

            var task = middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.AreEqual(null, task.Exception);
        }
        [TestMethod]
        public void ShouldNotThrowWhenIncludeServerAuthorizationIsTrueAndAuthorizationIsEmpty()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var body = "hello world";
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var ms = new MemoryStream();
            ms.Write(bodyBytes, 0, bodyBytes.Length);
            ms.Flush();
            ms.Seek(0, SeekOrigin.Begin);

            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));
            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.SetHeader("Authorization", new[] { "" });

            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "post";
            request.Body = ms;
            request.SetHeader("Host", new string[] { "example.com" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.ContentType = "text/plain";

            var response = (OwinResponse)context.Response;

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => Task.FromResult(credential),
                               IncludeServerAuthorization = true
                           }
                        );

            var task = middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.AreEqual(null, task.Exception);
        }

        [TestMethod]
        public void ShouldAuthenticateServer()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "sha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var logger = new Logger();
            var builder = new AppBuilderFactory().Create();
            builder.SetLoggerFactory(new LoggerFactory(logger));

            var ts = Hawk.ConvertToUnixTimestamp(DateTime.Now);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "j4h3g2", credential, "header");

            var context = new OwinContext();
            var request = (OwinRequest)context.Request;
            request.Set<Action<Action<object>, object>>("server.OnSendingHeaders", RegisterForOnSendingHeaders);
            request.Method = "get";
            request.SetHeader("Host", new string[] { "example.com" });
            request.SetUri(new Uri("http://example.com:8080/resource/4?filter=a"));
            request.SetHeader("Authorization", new string[] { "Hawk " + 
                string.Format("id = \"456\", ts = \"{0}\", nonce=\"j4h3g2\", mac = \"{1}\", ext = \"hello\"",
                ts, mac)});

            var response = (OwinResponse)context.Response;
            response.Body = new MemoryStream();

            var middleware = new HawkAuthenticationMiddleware(
                            new AppFuncTransition((env) =>
                            {
                                response.StatusCode = 200;
                                
                                var content = Encoding.UTF8.GetBytes("foo");

                                response.Body.Write(content, 0, content.Length);

                                return Task.FromResult<object>(null);
                            }),
                           builder,
                           new HawkAuthenticationOptions
                           {
                               Credentials = (id) => Task.FromResult(credential),
                               IncludeServerAuthorization = true,
                           }
                        );

            middleware.Invoke(context);

            Assert.AreEqual(200, response.StatusCode);
            Assert.IsTrue(logger.Messages.Count == 0);
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

        private void RegisterForOnSendingHeaders(Action<object> callback, object state)
        {
            IList<Tuple<Action<object>, object>> actions = OnSendingHeadersActions;
            actions.Add(new Tuple<Action<object>, object>(callback, state));
        }

        class LoggerFactory : ILoggerFactory
        {
            Logger logger;

            public LoggerFactory(Logger logger)
            {
                this.logger = logger;
            }

            public ILogger Create(string name)
            {
                return this.logger;
            }
        }

        class Logger : ILogger
        {
            public List<string> Messages = new List<string>();

            public bool WriteCore(System.Diagnostics.TraceEventType eventType, int eventId, object state, Exception exception, Func<object, Exception, string> formatter)
            {
                Messages.Add(state.ToString());

                return true;
            }
        }
    }

    public static class OwinRequestExtensions
    {
        public static void SetUri(this OwinRequest request, Uri uri, bool ignoreHost = false)
        {
            request.QueryString = new QueryString((!string.IsNullOrWhiteSpace(uri.Query)) ? uri.Query.Substring(1) : "");
            request.Scheme = uri.Scheme;
            if (!ignoreHost)
                request.Host = new HostString(uri.Host + ":" + uri.Port);
            request.PathBase = new PathString("");
            request.Path = new PathString(uri.PathAndQuery.Replace(uri.Query, ""));
        }

        public static void SetHeader(this OwinRequest request, string name, string[] values)
        {
            var headers = request.Get<IDictionary<string, string[]>>("owin.RequestHeaders");
            if (headers == null)
            {
                headers = new Dictionary<string, string[]>();
                request.Set<IDictionary<string, string[]>>("owin.RequestHeaders", headers);
            }

            headers.Add(name, values);
        }
    }
}
