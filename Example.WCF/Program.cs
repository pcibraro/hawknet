using HawkNet;
using HawkNet.WCF;
using Microsoft.ServiceModel.Web;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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

            var credential = new HawkCredential
            {
                Id = "id",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "hmacsha256",
                User = "steve"
            };

            Func<string, HawkCredential> credentials = (id) => credential;

            host.Interceptors.Add(new HawkRequestInterceptor(
                credentials, 
                false,
                (message) => !message.Properties.Via.AbsoluteUri.EndsWith("$metadata")));

            host.Open();

            foreach (ServiceEndpoint endpoint in host.Description.Endpoints)
            {
                Console.WriteLine("Listening at " + endpoint.Address.Uri.AbsoluteUri);
            }

            Thread.Sleep(1000);

            MakeCall(credential);

            Console.WriteLine("Press a key to exit");
            Console.ReadLine();
        }

        static void MakeCall(HawkCredential credential)
        {
            var requestUri = new Uri("http://localhost:8090/CustomerOData/Customers");

            var request = (HttpWebRequest)WebRequest.Create(requestUri);

            var hawk = Hawk.GetAuthorizationHeader("localhost:8090",
                "GET",
                requestUri,
                credential);

            request.Headers.Add("Authorization", "Hawk " + hawk);
            
            var response = (HttpWebResponse)request.GetResponse();

            if (response.StatusCode == HttpStatusCode.OK)
            {
                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var content = sr.ReadToEnd();

                    Console.WriteLine("Received " + content);
                }
            }
            else
            {
                Console.WriteLine("Http Status code " + response.StatusCode);
            }

            response.Close();
        }
    }
}
