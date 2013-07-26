using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet.Owin
{
    public class HawkAuthenticationOptions : AuthenticationOptions
    {
        public const string Scheme = "Hawk";

        public HawkAuthenticationOptions()
            : base(Scheme)
        {
        }

        public Func<string, HawkCredential> Credentials { get; set; }
    }
}
