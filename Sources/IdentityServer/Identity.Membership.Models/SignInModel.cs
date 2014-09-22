using System;
using System.ComponentModel.DataAnnotations;

namespace Identity.Membership.Models
{
    public class SignInModel
    {
        private bool? _isSigninRequest;

        [Required]
        [Display(Name = "UserName")]
        public string UserName { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Display(Name = "Remember Me")]
        public bool EnableSSO { get; set; }

        public bool IsSigninRequest
        {
            get
            {
                if (_isSigninRequest == null)
                {
                    _isSigninRequest = !String.IsNullOrWhiteSpace(ReturnUrl);
                }
                return _isSigninRequest.Value;
            }
            set
            {
                _isSigninRequest = value;
            }
        }

        public string ReturnUrl { get; set; }

        public bool ShowClientCertificateLink { get; set; }
    }
}
