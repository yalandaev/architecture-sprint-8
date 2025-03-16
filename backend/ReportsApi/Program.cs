using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        IdentityModelEventSource.ShowPII = true;
        options.Authority = "http://localhost:8080/realms/reports-realm";
        options.Audience = "reports-api";
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "http://localhost:8080/realms/reports-realm",
            RoleClaimType = "roles"
        };
        
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine("Authentication failed: " + context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                if (context.Principal?.HasClaim(c => c.Type == "realm_access") == true)
                {
                    var realmAccessJson = context.Principal.Claims.FirstOrDefault(c => c.Type == "realm_access")?.Value;
                    if (!string.IsNullOrEmpty(realmAccessJson))
                    {
                        try
                        {
                            var realmAccess = System.Text.Json.JsonSerializer.Deserialize<RealmAccess>(realmAccessJson);
                            if (realmAccess?.Roles != null)
                            {
                                foreach (var role in realmAccess.Roles)
                                {
                                    context.Principal?.Identities.First().AddClaim(new System.Security.Claims.Claim("roles", role));
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to deserialize realm_access: {ex.Message}");
                        }
                    }
                }
                
                Console.WriteLine("Token validated for user: " + context.Principal?.Identity?.Name);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ProtheticUser", policy =>
    {
        policy.RequireRole("prothetic_user");
    });
});

builder.Services.AddOpenApi();

var app = builder.Build();

app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/reports", () =>
    {
        var forecast = Enumerable.Range(1, 5).Select(index =>
                new WeatherForecast
                (
                    DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                    Random.Shared.Next(-20, 55),
                    summaries[Random.Shared.Next(summaries.Length)]
                ))
            .ToArray();
        return forecast;
    })
    .WithName("GetWeatherForecast")
    .RequireAuthorization("ProtheticUser");

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

public class RealmAccess
{
    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = new();
}