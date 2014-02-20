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
            this.TimeskewInSeconds = 60;
            this.IncludeServerAuthorization = false;
        }

        public Func<string, Task<HawkCredential>> Credentials { get; set; }

        public int TimeskewInSeconds
        {
            get;
            set;
        }

        public bool IncludeServerAuthorization
        {
            get;
            set;
        }
    }
}
