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
        public const string Issuer = "Chris";
        public const string Audience = "Użytkownicy aplikacji CarDealer";
        public const string Key = "Klucz szyfrujący tokeny JWT - uwaga powinien być bardzo skomplikowany, minimum to 16 znaków";
        public const string AuthSchemes = "Identity.Application" + "," + JwtBearerDefaults.AuthenticationScheme;
    }
}
