using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace GomLib.Models
{
    public class Conversation : GameObject
    {
        public List<Npc> Npcs { get; set; }
        public List<Placeable> Placeables { get; set; }
        public List<Quest> QuestStarted { get; set; }
        public List<Quest> QuestEnded { get; set; }
        public List<Quest> QuestProgressed { get; set; }

        public List<DialogNode> RootNodes { get; set; }
        public List<DialogNode> DialogNodes { get; set; }
        public Dictionary<int, DialogNode> NodeLookup { get; set; }

        public Conversation()
        {
            Npcs = new List<Npc>();
            Placeables = new List<Placeable>();
            QuestStarted = new List<Quest>();
            QuestEnded = new List<Quest>();
            QuestProgressed = new List<Quest>();
            RootNodes = new List<DialogNode>();
            DialogNodes = new List<DialogNode>();
            NodeLookup = new Dictionary<int, DialogNode>();
        }
    }
}
