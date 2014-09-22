using System;
using System.ComponentModel.DataAnnotations;
using Identity.Membership.Interfaces;

namespace Identity.Membership.Configurations
{
    public class WSTrustConfiguration : ProtocolConfiguration, IWSTrustConfiguration
    {
        public WSTrustConfiguration()
        {
            EnableDelegation = true;
        }

        [Display(Name = "EnableMessageSecurity", Description = "EnableMessageSecurityDescription")]
        public bool EnableMessageSecurity { get; set; }

        [Display(Name = "EnableMixedModeSecurity", Description = "EnableMixedModeSecurityDescription")]
        public bool EnableMixedModeSecurity { get; set; }

        [Display(Name = "EnableClientCertificateAuthentication", Description = "EnableClientCertificateAuthenticationDescription")]
        public bool EnableClientCertificateAuthentication { get; set; }

        [Display(Name = "EnableFederatedAuthentication", Description = "EnableFederatedAuthenticationDescription")]
        public bool EnableFederatedAuthentication { get; set; }

        [Display(Name = "EnableDelegation", Description = "EnableDelegationDescription")]
        public Boolean EnableDelegation { get; set; }
    }
}
