using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;
using System.Threading;

using MongoDB.Bson;
using MongoDB.Driver;

namespace NexusToRServer
{
    class Database
    {
        public static string connectionString = "mongodb://localhost";

        public static MongoServer Server { get; set; }
        public static MongoDatabase ADatabase { get; set; }

        public static void Initialize()
        {
            Server = MongoServer.Create(connectionString);

            var credentials = new MongoCredentials("nexus", "sJy82lA29");
            ADatabase = Server.GetDatabase("nexustor", credentials);
        }


    }
}
