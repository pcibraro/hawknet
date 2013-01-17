using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet
{
    /// <summary>
    /// Contains private information about an user 
    /// </summary>
    public class HawkCredential
    {
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

        /// <summary>
        /// Additional Claims
        /// </summary>
        public Claim[] AdditionalClaims { get; set; }
    }
}
