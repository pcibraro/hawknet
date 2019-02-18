using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

#if NET45 || CORE
using System.Security.Claims;
using System.Threading.Tasks;
#endif

namespace HawkNet
{
    /// <summary>
    /// Contains private information about an user 
    /// </summary>
    public class HawkCredential
    {
        public HawkCredential()
        {
            this.User = string.Empty;
#if !NET45 && !CORE
            this.Roles = new string[] { };
#endif
        }

        /// <summary>
        /// Key Id
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Symmetric Key
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Hashing Algorithm
        /// </summary>
        public string Algorithm { get; set; }

        /// <summary>
        /// User name
        /// </summary>
        public string User { get; set; }

#if NET45 || CORE
        /// <summary>
        /// Additional Claims
        /// </summary>
        public Claim[] AdditionalClaims { get; set; }
#else
        /// <summary>
        /// User roles
        /// </summary>
        public string[] Roles { get; set; }
#endif
    }
}
