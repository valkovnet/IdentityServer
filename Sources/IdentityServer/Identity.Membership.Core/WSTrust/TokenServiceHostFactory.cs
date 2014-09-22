using System;
using System.IdentityModel.Configuration;
using System.Reflection;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using Identity.Membership.Configurations;
using Microsoft.IdentityModel.Protocols.WSTrust.Bindings;

namespace Identity.Membership.Core.WSTrust
{
    public class TokenServiceHostFactory : ServiceHostFactory
    {
        private const string WSTrustMixedUserName = "mixed/username";

        private const string WSTrustMessageUserName = "message/username";

        private const string WSTrustMixedCertificate = "mixed/certificate";

        private const string WSTrustMessageCertificate = "message/certificate";

        public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
        {            
            var configuration = new IdentityIdentityConfiguration();
            var config = CreateSecurityTokenServiceConfiguration(constructorString);
            var host = new WSTrustServiceHost(config, baseAddresses);

            // Behavior for load balancing support
            host.Description.Behaviors.Add(new UseRequestHeadersForMetadataAddressBehavior());

            // Modify address filter mode for load balancing
            var serviceBehavior = host.Description.Behaviors.Find<ServiceBehaviorAttribute>();
            serviceBehavior.AddressFilterMode = AddressFilterMode.Any;

            if (configuration.WSTrust.Enabled && configuration.WSTrust.EnableMixedModeSecurity)
            {
                if (configuration.WSTrust.EnableClientCertificateAuthentication)
                {
                    host.AddServiceEndpoint(typeof(IWSTrust13SyncContract),
                        new CertificateWSTrustBinding(SecurityMode.TransportWithMessageCredential), WSTrustMixedCertificate);
                }

                host.AddServiceEndpoint(typeof(IWSTrust13SyncContract),
                    new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential), WSTrustMixedUserName);                
            }

            // Configure a message security endpoint
            if (configuration.WSTrust.Enabled && configuration.WSTrust.EnableMessageSecurity)
            {
                var credential = new ServiceCredentials();
                credential.ServiceCertificate.Certificate = configuration.Keys.SigningCertificate;
                host.Description.Behaviors.Add(credential);

                if (configuration.WSTrust.EnableClientCertificateAuthentication)
                {
                    host.AddServiceEndpoint(typeof (IWSTrust13SyncContract),
                        new CertificateWSTrustBinding(SecurityMode.Message), WSTrustMessageCertificate);
                }

                host.AddServiceEndpoint(typeof(IWSTrust13SyncContract),
                    new UserNameWSTrustBinding(SecurityMode.Message), WSTrustMessageUserName);
            }

            return host;
        }

        protected virtual SecurityTokenServiceConfiguration CreateSecurityTokenServiceConfiguration(string constructorString)
        {
            Type type = Type.GetType(constructorString, true);
            if (!type.IsSubclassOf(typeof(SecurityTokenServiceConfiguration)))
            {
                throw new InvalidOperationException("SecurityTokenServiceConfiguration");
            }

            return (Activator.CreateInstance(
                type,
                BindingFlags.CreateInstance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance,
                null,
                null,
                null) as SecurityTokenServiceConfiguration);
        }
    }
}
