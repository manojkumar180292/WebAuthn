using Microsoft.EntityFrameworkCore;
using WebAuthnDemo.Data;

using WebAuthnDemo.Services;

var builder = WebApplication.CreateBuilder(args);

// Set up SQLite connection string
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite("Data Source=app.db"));


// Register FidoService for WebAuthn processing
builder.Services.AddScoped<FidoService>();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Set the session timeout duration
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true; // Required for some browsers and when GDPR is enabled
});

// Add other services like MVC, etc.
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
app.UseSession();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Register}/{id?}");

app.MapRazorPages();

app.Run();
