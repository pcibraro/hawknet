using HawkNet;
using HawkNet.WCF;
using Microsoft.ServiceModel.Web;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;
using System.Threading;

namespace Example.WCF
{
    class Program
    {
        static void Main(string[] args)
        {
            var host = new WebServiceHost2(typeof(CustomerDataService), 
                true, 
                new Uri("http://localhost:8090/CustomerOData"));

            var host2 = new WebServiceHost2(typeof(HelloWorldService),
                true,
                new Uri("http://localhost:8091/HelloService"));

            var credential = new HawkCredential
            {
                Id = "id",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "sha256",
                User = "steve"
            };

            Func<string, HawkCredential> credentials = (id) => credential;

            host.Interceptors.Add(new HawkRequestInterceptor(
                credentials, 
                false,
                (message) => !message.Properties.Via.AbsoluteUri.EndsWith("$metadata")));

            host2.Interceptors.Add(
                new HawkRequestInterceptor(
                    credentials,
                    false,
                    (message) => true));

            host.Open();
            host2.Open();

            foreach (ServiceEndpoint endpoint in host.Description.Endpoints)
            {
                Console.WriteLine("Listening at " + endpoint.Address.Uri.AbsoluteUri);
            }

            foreach (ServiceEndpoint endpoint in host2.Description.Endpoints)
            {
                Console.WriteLine("Listening at " + endpoint.Address.Uri.AbsoluteUri);
            }

            Thread.Sleep(1000);
            
            MakeCall(credential);

            MakeCallWithBehavior();

            Console.WriteLine("Press a key to exit");
            Console.ReadLine();
        }

        static void MakeCallWithBehavior()
        {
            ChannelFactory<IHelloWorld> factory = new ChannelFactory<IHelloWorld>("hello");
            var proxy = factory.CreateChannel();
            var response = proxy.Hello();

            Console.WriteLine("Response " + response);

            ((IDisposable)proxy).Dispose();
        }

        static void MakeCall(HawkCredential credential)
        {
            var requestUri = new Uri("http://localhost:8090/CustomerOData/Customers");

            var request = (HttpWebRequest)WebRequest.Create(requestUri);

            var hawk = Hawk.GetAuthorizationHeader("localhost:8090",
                "GET",
                requestUri,
                new HawkCredential
                {
                    Algorithm = "sha256",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
                });

            request.Headers.Add("Authorization", "Hawk " + hawk);
            
            try
            {
                var response = (HttpWebResponse)request.GetResponse();
            
                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var content = sr.ReadToEnd();

                    Console.WriteLine("Received " + content);
                }

                response.Close();
            
            }
            catch(WebException ex)
            {
                var response = ((HttpWebResponse)ex.Response);

                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var content = sr.ReadToEnd();

                    Console.WriteLine("Received " + content);
                }

                response.Close();
            }

            
        }
    }
}
