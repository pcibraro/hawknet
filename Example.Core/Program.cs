using HawkNet;
using System;
using System.IO;
using System.Net;

namespace Example.Core
{
    class Program
    {
        static void Main(string[] args)
        {
            var credential = new HawkCredential
            {
                Id = "id",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "sha256",
                User = "steve"
            };

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
            catch (WebException ex)
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
