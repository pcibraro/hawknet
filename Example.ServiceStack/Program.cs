using HawkNet;
using HawkNet.ServiceStack;
using ServiceStack.ServiceInterface;
using ServiceStack.WebHost.Endpoints;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

namespace Example.ServiceStack
{
    class Program
    {
        public class Hello
        {
            public string Name { get; set; }
        }

        public class HelloResponse
        {
            public string Result { get; set; }
        }

        [HawkRequestFilter(typeof(HawkCredentialRepository))]
        public class HelloService : Service
        {
            public object Any(Hello request)
            {
                Console.WriteLine("Authenticated " + Thread.CurrentPrincipal.Identity.Name);

                return new HelloResponse { Result = "Hello, " + request.Name };
            }
        }

        //Define the Web Services AppHost
        public class AppHost : AppHostHttpListenerBase
        {
            public AppHost() : base("StarterTemplate HttpListener", typeof(HelloService).Assembly) { }

            public override void Configure(Funq.Container container)
            {
                Routes
                    .Add<Hello>("/hello")
                    .Add<Hello>("/hello/{Name}");
            }
        }
        
        static void Main(string[] args)
        {
            var listeningOn = args.Length == 0 ? "http://*:1337/" : args[0];
            var appHost = new AppHost();
            appHost.Init();
            appHost.Start(listeningOn);

            Console.WriteLine("AppHost Created at {0}, listening on {1}", DateTime.Now, listeningOn);

            MakeCall(new HawkNet.HawkCredential
            {
                Id = "id",
                Key = "AF57A1E8DA444A98A6F35128C5027B64",
                Algorithm = "hmacsha256",
                User = "steve"
            });

            Console.ReadLine();

        }

        static void MakeCall(HawkCredential credential)
        {
            var requestUri = new Uri("http://localhost:1337/hello/john");

            var request = (HttpWebRequest)WebRequest.Create(requestUri);

            var hawk = Hawk.GetAuthorizationHeader("localhost",
                "GET",
                requestUri,
                credential);

            request.Headers.Add("Authorization", "Hawk " + hawk);

            var response = (HttpWebResponse)request.GetResponse();

            Console.WriteLine("Http Status code " + response.StatusCode);

            response.Close();
        }
    }

    public class HawkCredentialRepository : IHawkCredentialRepository
    {
        public HawkNet.HawkCredential Get(string identifier)
        {
            return new HawkNet.HawkCredential
            {
                Id = identifier,
                Key = "AF57A1E8DA444A98A6F35128C5027B64",
                Algorithm = "hmacsha256",
                User = "steve"
            };
        }
    }
}
