using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NexusToRServer.NET
{
    public abstract class TORGameClientPacket : IPacket
    {

        public abstract void RunImplementation();
        public abstract void ReadImplementation();
        public abstract PacketType GetType();

        private UInt32 _component;

        public UInt32 Component
        {
            get { return _component; }
            set { _component = value; }
        }

        public override bool Read()
        {
            try
            {
                ReadImplementation();
                return true;
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, "Failed reading '{0}':\n{1}", GetType().ToString(), ex.ToString());
            }
            return false;
        }

        public override void Run()
        {
            try
            {
                RunImplementation();

                // TODO: Possibly spawn protection
            }
            catch(Exception e)
            {
                Log.Write(LogLevel.Error, "Failed running '{0}'\n{1}", GetType().ToString(), e);

                // TODO: Check if the error occured when the player was entering the world
                // If so, kick him out of the game
            }
        }
    }
}
