using HawkNet.WebApi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HawkNet;

namespace Example
{
    internal class HawkCredentialRepository : IHawkCredentialRepository
    {
        public Task<HawkCredential> GetCredentialsAsync(string id)
        {
            return Task.FromResult(new HawkCredential
            {
                Id = id,
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "sha256",
                User = "steve"
            });
        }
    }
}
