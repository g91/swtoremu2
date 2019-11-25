using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NexusToRServer.TOR
{
    public class Character
    {
        public string _name;
        public UInt64 _id, _unk01, _unk02, _unk03, _unk04;
        public Byte _unk05, _unk06, _unk07;
        public byte[] Blob;
        public UInt16 _unk08;
        public List<UInt64> UnkList;

        public Character()
        {
            UnkList = new List<UInt64>();
        }

        public Character(UInt64 ID)
        {
            UnkList = new List<UInt64>();
            _id = ID;
            // TODO: Load char data from DB
        }
    }
}
