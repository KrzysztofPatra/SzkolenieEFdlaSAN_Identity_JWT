using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CarDealerView.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Identity;
using IdentitySample.Models.AccountViewModels;
using Microsoft.CodeAnalysis.FlowAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;

namespace CarDealerView
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            //Niektóre polecenia narzêdzi EF Core (na przyk³ad polecenia migracji ) wymagaj¹ utworzenia wyst¹pienia pochodnego w DbContext czasie projektowania w celu zebrania szczegó³owych informacji o typach jednostek aplikacji i sposobie ich mapowania na schemat bazy danych.

            services.AddDbContext<CarDealerDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<CarDealerDbContext>()
                .AddDefaultTokenProviders();

            //services.AddAuthentication() //for .aspnetcore 3.0
            //    .AddCookie(cfg => cfg.SlidingExpiration = true)
            //    .AddJwtBearer(cfg =>
            //    {
            //        cfg.TokenWalidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
            //        {
            //            ValidIssuer = JwtConfiguration.Issuer,
            //            ValidAudience = JwtConfiguration.Audience,
            //            IssuerSigningKey = new SymetricSecurityKey(Encoding.UTF8.GetBytes(key))
            //        };
            //    });
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
             .AddJwtBearer(x =>
             {
                 x.RequireHttpsMetadata = false;
                 x.SaveToken = true;
                 x.TokenValidationParameters = new TokenValidationParameters
                 {
                     ValidateIssuerSigningKey = true,
                     IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtConfiguration.Key)),
                     ValidateIssuer = false,
                     ValidateAudience = false
                 };
             });
            //services.AddAuthentication();
            services.AddAuthorization();

            services.AddMvc()
                    .AddSessionStateTempDataProvider();
            services.AddSession();

        }

       




        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            //Add User session
            app.UseSession();

            //Add JWTtoken to all incoming HTTP Request Header
            app.Use(async (context, next) =>
            {
                var JWTtoken = context.Session.GetString("JWTtoken");
                if (!string.IsNullOrEmpty(JWTtoken))
                {
                    context.Request.Headers.Add("Authorization", "Bearer " + JWTtoken);
                }
                await next();
            });

            app.UseAuthorization();
            app.UseAuthentication();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
