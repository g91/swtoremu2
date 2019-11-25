using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NexusToRServer
{
    public static class TransUserTable
    {
        private static List<TransUser> _users = new List<TransUser>();

        public static TransUser ByUN(string username)
        {
            return _users.Find(u => u.Username == username);
        }

        public static TransUser ByHash(string hash)
        {
            return _users.Find(u => u.ConnectionHash == hash);
        }

        public static bool ContainsHash(string hash)
        {
            return _users.Exists(u => u.ConnectionHash == hash);
        }

        public static void Add(TransUser user)
        {
            _users.Add(user);
        }

        public static void RemoveByHash(string hash)
        {
            var tUser = _users.Find(u => u.ConnectionHash == hash);
            _users.Remove(tUser);
        }

    }

    public class TransUser
    {
        public TransUser(string username)
        {
            this.Username = username;
        }

        public string Username { get; set; }
        public string ConnectionHash { get; set; }
    }
}
