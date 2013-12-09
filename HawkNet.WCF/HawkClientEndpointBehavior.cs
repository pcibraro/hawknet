using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.ServiceModel.Channels;
using System.ServiceModel.Configuration;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;

namespace HawkNet.WCF
{
    public class HawkClientEndpointBehavior : Attribute, IEndpointBehavior
    {
        public string Id { get; set; }

        public string Key { get; set; }

        public string Algorithm { get; set; }

        public void AddBindingParameters(ServiceEndpoint endpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.ClientRuntime clientRuntime)
        {
            clientRuntime.MessageInspectors.Add(new HawkClientMessageInspector(
                new HawkCredential
                {
                    Id = this.Id,
                    Algorithm = this.Algorithm,
                    Key = this.Key
                }));
        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.EndpointDispatcher endpointDispatcher)
        {
        }

        public void Validate(ServiceEndpoint endpoint)
        {
        }

        internal class HawkClientMessageInspector : IClientMessageInspector
        {
            HawkCredential credential;

            public HawkClientMessageInspector(HawkCredential credential)
            {
                this.credential = credential;
            }
                        
            public void AfterReceiveReply(ref System.ServiceModel.Channels.Message reply, object correlationState)
            {
            }

            public object BeforeSendRequest(ref System.ServiceModel.Channels.Message request, System.ServiceModel.IClientChannel channel)
            {
                var requestMessage = (HttpRequestMessageProperty)request.Properties[HttpRequestMessageProperty.Name];

                if (requestMessage == null)
                {
                    throw new InvalidOperationException("The HttpRequestMessageProperty is not found. Make sure to add a webHttp behavior before the Hawk behavior");
                }

                var to = request.Headers.To;

                var hawk = Hawk.GetAuthorizationHeader(
                    to.Host,
                    requestMessage.Method,
                    to,
                    this.credential);

                requestMessage.Headers.Add("Authorization", "Hawk " + hawk);

                return null;
            }
        }
    }

    public class HawkClientBehaviorExtensionElement : BehaviorExtensionElement
    {
        public HawkClientBehaviorExtensionElement()
            : base()
        {
        }

        [ConfigurationProperty("id", IsRequired=true)]
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

        public override Type BehaviorType
        {
            get { return typeof(HawkClientEndpointBehavior); }
        }

        protected override object CreateBehavior()
        {
            return new HawkClientEndpointBehavior()
                {
                    Id = this.Id,
                    Key= this.Key,
                    Algorithm = this.Algorithm
                };
        }
    }
}
