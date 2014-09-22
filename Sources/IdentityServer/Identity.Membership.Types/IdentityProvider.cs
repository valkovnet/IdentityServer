using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Identity.Membership.Types
{
    public enum IdentityProviderTypes
    {
        WSStar = 1,
        //public const string OpenId = "OpenId";
        OAuth2 = 2
    }

    public enum OAuth2ProviderTypes
    {
        Google = 1,
        Facebook = 2,
        Live = 3,
    }

    public class IdentityProvider : IValidatableObject
    {
        [UIHint("HiddenInput")]
        public int ID { get; set; }

        [Required]
        [Display(Order = 1, Name = "Name", Description = "NameDescription")]
        public string Name { get; set; }

        [Required]
        [Display(Order = 2, Name = "DisplayName", Description = "DisplayNameDescription")]
        public string DisplayName { get; set; }

        [Display(Order = 3, Name = "Enabled", Description = "EnabledDescription")]
        public bool Enabled { get; set; }

        [Display(Order = 4, Name = "ShowInHrdSelection", Description = "ShowInHrdSelectionDescription")]
        public bool ShowInHrdSelection { get; set; }

        [Required]
        [UIHint("Enum")]
        [Display(Order = 5, Name = "Type", Description = "TypeDescription")]
        public IdentityProviderTypes Type { get; set; }

        [Display(Order = 6, Name = "WSFederationEndpoint", Description = "WSFederationEndpointDescription")]
        [AbsoluteUri]
        public string WSFederationEndpoint { get; set; }

        string _IssuerThumbprint;
        [UIHint("Thumbprint")]
        [Display(Order = 7, Name = "IssuerThumbprint", Description = "IssuerThumbprintDescription")]
        public string IssuerThumbprint
        {
            get
            {
                return _IssuerThumbprint;
            }
            set
            {
                _IssuerThumbprint = value;
                if (_IssuerThumbprint != null) _IssuerThumbprint = _IssuerThumbprint.Replace(" ", "");
            }
        }

        [Display(Order = 8, Name = "ProviderType", Description = "ProviderTypeDescription")]
        [UIHint("Enum")]
        public OAuth2ProviderTypes? ProviderType { get; set; }

        [Display(Order = 9, Name = "ClientID", Description = "ClientIDDescription")]
        public string ClientID { get; set; }

        [Display(Order = 10, Name = "ClientSecret", Description = "ClientSecretDescription")]
        public string ClientSecret { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            List<ValidationResult> errors = new List<ValidationResult>();

            if (this.Type == IdentityProviderTypes.WSStar)
            {
                if (String.IsNullOrEmpty(this.WSFederationEndpoint))
                {
                    errors.Add(new ValidationResult("WSFederationEndpointRequiredError", new string[] { "WSFederationEndpoint" }));
                }
                if (String.IsNullOrEmpty(this.IssuerThumbprint))
                {
                    errors.Add(new ValidationResult("IssuerThumbprintRequiredError", new string[] { "IssuerThumbprint" }));
                }
            }
            if (this.Type == IdentityProviderTypes.OAuth2)
            {
                if (String.IsNullOrEmpty(this.ClientID))
                {
                    errors.Add(new ValidationResult("ClientIDRequiredError", new string[] { "ClientID" }));
                }
                if (String.IsNullOrEmpty(this.ClientSecret))
                {
                    errors.Add(new ValidationResult("ClientSecretRequiredError", new string[] { "ClientSecret" }));
                }
                if (this.ProviderType == null)
                {
                    errors.Add(new ValidationResult("ProviderTypeRequiredError", new string[] { "ProfileType" }));
                }
            }

            return errors;
        }
    }
}
