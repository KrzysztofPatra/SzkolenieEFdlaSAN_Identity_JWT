using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CarDealerView.Models
{
    public class JwtConfiguration
    {
        public const string Issuer = "MVS";
        public const string Audience = "ApiUser";
        public const string Key = "12345678901234567890";
        public const string AuthSchemes = "Identity.Application" + "," + JwtBearerDefaults.AuthenticationScheme;
    }
}
