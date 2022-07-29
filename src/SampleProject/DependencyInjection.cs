using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SampleProject.Configurations;
using SampleProject.Data;
using SampleProject.Infrastructure;
using SampleProject.Infrastructure.AppSettingsModels;

namespace Microsoft.Extensions.DependencyInjection;

public static class DependencyInjection
{
    public static void AddDatabase<TApplicationDbContext, TIdentityUser>(
        this IServiceCollection services,
        IConfiguration configuration)
        where TIdentityUser : IdentityUser
        where TApplicationDbContext : IdentityDbContext<TIdentityUser>
    {
        DatabaseProviderOptions dbProviderOptions = new ();
        configuration.GetSection("DatabaseProvider").Bind(dbProviderOptions);

        if (dbProviderOptions.Provider == DatabaseProviderOptions.Sqlite)
        {
            services.AddDbContext<TApplicationDbContext>(options =>
            {
                options.UseSqlite(
                    configuration.GetConnectionString(DatabaseProviderOptions.SqliteConnectionStringName));
            });
        }

        else if (dbProviderOptions.Provider == DatabaseProviderOptions.PostgreSQL)
        {
            services.AddDbContext<TApplicationDbContext>(options =>
            {
                options.UseNpgsql(
                    configuration.GetConnectionString(DatabaseProviderOptions.PostgreSQLConnectionStringName));
            });
        }

        else if (dbProviderOptions.Provider == DatabaseProviderOptions.MSSQL)
        {
            services.AddDbContext<TApplicationDbContext>(options =>
            {
                options.UseSqlServer(
                    configuration.GetConnectionString(DatabaseProviderOptions.MSSQLConnectionStringName));
            });
        }

        else if (dbProviderOptions.Provider == DatabaseProviderOptions.MySQL)
        {
            services.AddDbContext<TApplicationDbContext>(options =>
            {
                options.UseMySQL(
                    configuration.GetConnectionString(DatabaseProviderOptions.MySQLConnectionStringName));
            });
        }
        else
        {
            throw new Exception("Invalid Database Provider");
        }
    }

    public static void AddCustomIdentity<TUser, TRole, TApplicationDbContext, TApplicationUserClaimsPrincipalFactory>(
        this IServiceCollection services,
        IConfiguration configuration)
        where TUser : IdentityUser
        where TRole : IdentityRole
        where TApplicationDbContext : IdentityDbContext<TUser>
        where TApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<TUser, TRole>
    {
        services.Configure<CookiePolicyOptions>(options =>
        {
            // This lambda determines whether user consent for non-essential cookies is needed
            // for a given request.
            options.CheckConsentNeeded = _ => true;
            options.MinimumSameSitePolicy = SameSiteMode.Strict;
        });

        services.AddDefaultIdentity<TUser>()
            .AddRoles<TRole>()
            .AddEntityFrameworkStores<TApplicationDbContext>();

        services.AddScoped<IUserClaimsPrincipalFactory<TUser>, TApplicationUserClaimsPrincipalFactory>();

        services.Configure<IdentityOptions>(options =>
        {
            // Default Lockout settings.
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;

            // Default Password settings.
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequiredLength = 6;
            options.Password.RequiredUniqueChars = 1;

            // Default SignIn settings.
            options.SignIn.RequireConfirmedEmail = false;
            options.SignIn.RequireConfirmedPhoneNumber = false;

            // Default User settings.
            options.User.AllowedUserNameCharacters =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

            options.User.RequireUniqueEmail = true;
        });

        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = "SampleProject.AppCookie";
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
            // You might want to only set the application cookies over a secure connection:
            // options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            options.SlidingExpiration = true;
        });

        // As per https://github.com/aspnet/AspNetCore/issues/5828
        // the settings for the cookie would get overwritten if using the default UI so
        // we need to "post-configure" the authentication cookie
        services.PostConfigure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme, options =>
        {
            options.AccessDeniedPath = "/access-denied";
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";

            options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
        });

        services.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
        });
    }

    public static void AddWebUI(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders =
                ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        });

        services.Configure<ScriptTags>(configuration.GetSection(nameof(ScriptTags)));

        services.AddDataProtection()
            .PersistKeysToDbContext<ApplicationDbContext>();

        services.AddAntiforgery();

        services.AddControllersWithViews(options =>
        {
            // Slugify routes so that we can use /employee/employee-details/1 instead of
            // the default /Employee/EmployeeDetails/1
            //
            // Using an outbound parameter transformer is a better choice as it also allows
            // the creation of correct routes using view helpers
            options.Conventions.Add(
                new RouteTokenTransformerConvention(
                    new SlugifyParameterTransformer()));

            // Enable Antiforgery feature by default on all controller actions
            options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
        });

        services.AddRazorPages(options =>
            {
                options.Conventions.AddAreaPageRoute("Identity", "/Account/Register", "/register");
                options.Conventions.AddAreaPageRoute("Identity", "/Account/Login", "/login");
                options.Conventions.AddAreaPageRoute("Identity", "/Account/Logout", "/logout");
                options.Conventions.AddAreaPageRoute("Identity", "/Account/ForgotPassword", "/forgot-password");
            })
            .AddSessionStateTempDataProvider();

        // You probably want to use in-memory cache if not developing using docker-compose
        services.AddMemoryCache();
        //services.AddDistributedRedisCache(action => { action.Configuration = Configuration["Redis:InstanceName"]; });

        services.AddSession(options =>
        {
            // Set a short timeout for easy testing.
            options.IdleTimeout = TimeSpan.FromMinutes(60);
            options.Cookie.Name = "SampleProject.SessionCookie";
            // You might want to only set the application cookies over a secure connection:
            // options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.HttpOnly = true;
            // Make the session cookie essential
            options.Cookie.IsEssential = true;
        });
    }
}