using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet
{
    public class HawkCredential
    {
        public string Id { get; set; }

        public string Key { get; set; }

        public string Algorithm { get; set; }

        public string User { get; set; }

        public Claim[] AdditionalClaims { get; set; }
    }
}
