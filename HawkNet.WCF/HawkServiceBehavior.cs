using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.ServiceModel.Channels;
using System.ServiceModel.Configuration;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Threading.Tasks;
using System.ServiceModel;
using System.Diagnostics;
using System.IdentityModel.Configuration;

namespace HawkNet.WCF
{
    public class HawkCredentialConfigurationElement : ConfigurationElement
    {
        [ConfigurationProperty("id", IsRequired = true)]
        public string Id
        {
            get { return (string)this["id"]; }
            set { this["id"] = value; }
        }

        [ConfigurationProperty("algorithm", IsRequired = true)]
        public string Algorithm
        {
            get { return (string)this["algorithm"]; }
            set { this["algorithm"] = value; }
        }

        [ConfigurationProperty("key", IsRequired = true)]
        public string Key
        {
            get { return (string)this["key"]; }
            set { this["key"] = value; }
        }

        [ConfigurationProperty("user", IsRequired = true)]
        public string User
        {
            get { return (string)this["user"]; }
            set { this["user"] = value; }
        }
    }

    [ConfigurationCollection(typeof(HawkCredentialConfigurationElement), CollectionType = ConfigurationElementCollectionType.BasicMap)]
    public class HawkCredentialConfigurationElementCollection : ConfigurationElementCollection
    {
        public override ConfigurationElementCollectionType CollectionType
        {
            get { return ConfigurationElementCollectionType.BasicMap; }
        }

        protected override string ElementName
        {
            get
            {
                return "credential";
            }
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new HawkCredentialConfigurationElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return (element as HawkCredentialConfigurationElement).Id;
        }
    }

    public class HawkServiceBehavior : BehaviorExtensionElement, IServiceBehavior
    {
        [ConfigurationProperty("sendChallenge", DefaultValue = true)]
        public bool SendChallenge
        {
            get { return (bool)this["sendChallenge"]; }
            set { this["sendChallenge"] = value; }
        }

        [ConfigurationProperty("schemeOverride")]
        [RegexStringValidator("^(https?)?$")]
        public string SchemeOverride
        {
            get { return (string)this["schemeOverride"]; }
            set { this["schemeOverride"] = value; }
        }

        [ConfigurationProperty("timeskewInSeconds", DefaultValue = 60)]
        [IntegerValidator]
        public int TimeskewInSeconds
        {
            get { return (int)this["timeskewInSeconds"]; }
            set { this["timeskewInSeconds"] = value; }
        }
        
        [ConfigurationProperty("credentials", IsDefaultCollection = true, IsKey = false, IsRequired = false)]
        public HawkCredentialConfigurationElementCollection HawkCredentials
        {
            get
            {
                HawkCredentialConfigurationElementCollection hawkCredentials =
                (HawkCredentialConfigurationElementCollection)base["credentials"];
                return hawkCredentials;
            }
        }

        public override Type BehaviorType
        {
            get { return typeof(HawkServiceBehavior); }
        }

        protected override object CreateBehavior()
        {
            return this;
        }
        #region IServiceBehavior Members

        public void AddBindingParameters(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase, System.Collections.ObjectModel.Collection<ServiceEndpoint> endpoints, BindingParameterCollection bindingParameters)
        {

        }

        public virtual Func<string, HawkCredential> GetCredentialFunction()
        {
            var credentials = new Dictionary<string, HawkCredential>();

            foreach (HawkCredentialConfigurationElement hawkCredential in this.HawkCredentials)
            {
                credentials.Add(hawkCredential.Id,
                    new HawkCredential
                    {
                        Id = hawkCredential.Id,
                        Key = hawkCredential.Key,
                        Algorithm = hawkCredential.Algorithm,
                        User = hawkCredential.User
                    });
            }

            return (id) => (credentials.ContainsKey(id)) ? credentials[id] : null;
        }

        public void ApplyDispatchBehavior(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase)
        {
            var authenticationBehavior = serviceDescription.Behaviors.Find<ServiceAuthenticationBehavior>();
            var hawkAuthenticationManager = authenticationBehavior.ServiceAuthenticationManager as HawkAuthenticationManager;
            if (hawkAuthenticationManager == null)
            {
                hawkAuthenticationManager = new HawkAuthenticationManager(this.GetCredentialFunction(), this.TimeskewInSeconds, this.SchemeOverride);
                authenticationBehavior.ServiceAuthenticationManager = hawkAuthenticationManager;
            }

            ((IServiceBehavior)authenticationBehavior).ApplyDispatchBehavior(serviceDescription, serviceHostBase);

            var authorizationBehavior = serviceDescription.Behaviors.Find<ServiceAuthorizationBehavior>();
            var hawkAuthorizationManager = authorizationBehavior.ServiceAuthorizationManager as HawkAuthorizationManager;
            if (hawkAuthorizationManager == null)
            {
                authorizationBehavior.ServiceAuthorizationManager = new HawkAuthorizationManager(this.SendChallenge);
            }

            authorizationBehavior.PrincipalPermissionMode = PrincipalPermissionMode.Custom;

            ((IServiceBehavior)authorizationBehavior).ApplyDispatchBehavior(serviceDescription, serviceHostBase);
        }

        public void Validate(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase)
        {

        }

        #endregion

    }


}
