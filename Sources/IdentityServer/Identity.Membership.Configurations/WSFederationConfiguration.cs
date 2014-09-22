using System;
using System.ComponentModel.DataAnnotations;
using Identity.Membership.Interfaces;

namespace Identity.Membership.Configurations
{
    public class WSFederationConfiguration : ProtocolConfiguration, IWSFederationConfiguration
    {
        public WSFederationConfiguration()
        {
            Enabled = true;
            EnableFederation = true;
            EnableAuthentication = true;
            RequireSslForReplyTo = true;
        }

        [Display(Name = "EnableAuthentication", Description = "EnableAuthenticationDescription")]
        public bool EnableAuthentication { get; set; }

        [Display(Name = "EnableFederation", Description = "EnableFederationDescription")]
        public bool EnableFederation { get; set; }

        [Display(Name = "EnableHrd", Description = "EnableHrdDescription")]
        public bool EnableHrd { get; set; }

        [Display(Name = "AllowReplyTo", Description = "AllowReplyToDescription")]
        public bool AllowReplyTo { get; set; }

        [Display(Name = "RequireReplyToWithinRealm", Description = "RequireReplyToWithinRealmDescription")]
        public Boolean RequireReplyToWithinRealm { get; set; }

        [Display(Name = "RequireSslForReplyTo", Description = "RequireSslForReplyToDescription")]
        public Boolean RequireSslForReplyTo { get; set; }
    }
}
