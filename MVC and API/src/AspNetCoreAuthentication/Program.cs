﻿using System.IO;
using Microsoft.AspNetCore.Hosting;

namespace AspNetCoreAuthentication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                .UseKestrel()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>()
                //.UseUrls("http://localhost:3308")
                .Build();

            host.Run();
        }
    }
}
