using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using System.Xml;

namespace GomLib.Models
{
    public class Placeable : GameObject
    {
        public ulong NodeId { get; set; }
        public string Name { get; set; }

        public Conversation Conversation { get; set; }
        public Codex Codex { get; set; }
        public Profession RequiredProfession { get; set; }
        public int RequiredProfessionLevel { get; set; }
        public bool IsBank { get; set; }
        public bool IsMailbox { get; set; }
        public bool IsAuctionHouse { get; set; }
        public bool IsEnhancementStation { get; set; }
        public AuctionHouseNetwork AuctionNetwork { get; set; }
        public Faction Faction { get; set; }
        public int LootLevel { get; set; }
        public long LootPackageId { get; set; }
        public long WonkaPackageId { get; set; }
        public int DifficultyFlags { get; set; }
        public PlaceableCategory Category { get; set; }

        public HydraScript HydraScript { get; set; }

        public override int GetHashCode()
        {
            int result = NodeId.GetHashCode();
            result ^= Name.GetHashCode();
            if (Codex != null) { result ^= Codex.Id.GetHashCode(); }
            result ^= RequiredProfession.GetHashCode();
            result ^= RequiredProfessionLevel.GetHashCode();
            result ^= IsBank.GetHashCode();
            result ^= IsMailbox.GetHashCode();
            result ^= IsAuctionHouse.GetHashCode();
            result ^= IsEnhancementStation.GetHashCode();
            result ^= AuctionNetwork.GetHashCode();
            result ^= Faction.GetHashCode();
            result ^= LootLevel.GetHashCode();
            result ^= LootPackageId.GetHashCode();
            result ^= WonkaPackageId.GetHashCode();
            result ^= DifficultyFlags.GetHashCode();
            result ^= Category.GetHashCode();

            return result;
        }
    }
}
