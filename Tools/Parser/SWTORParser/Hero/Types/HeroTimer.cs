namespace SWTORParser.Hero.Types
{
    public class HeroTimer : HeroAnyValue
    {
        #region State enum

        public enum State
        {
            Off = 1,
            On = 2,
            Paused = 3,
        }

        #endregion

        public long _00;
        public uint _08;
        public bool _0C;
        public long _10;
        public long _18;
        public long _20;
        public long _28;
        public long _30;
        public ulong _38;
        public long _40;
        public long _48;

        public HeroTimer()
        {
            Type = new HeroType(HeroTypes.Timer);
        }

        public override string ValueText
        {
            get { return "--Data--"; }
        }

        public override void Deserialize(PackedStream2 stream)
        {
            hasValue = true;
            stream.Read(out _00);
            ulong num1;
            stream.Read(out num1);
            stream.Read(out _0C);
            stream.Read(out _10);
            stream.Read(out _18);
            stream.Read(out _20);
            stream.Read(out _28);
            stream.Read(out _30);
            long num2;
            stream.Read(out num2);
            stream.Read(out _38);
            if (num2 == 3735928559L)
            {
                stream.Read(out _40);
                stream.Read(out _48);
            }
            _08 = (uint) num1;
        }

        public override void Serialize(PackedStream2 stream)
        {
            ulong num1 = _08;
            long num2 = 3735928559L;
            stream.Write(_00);
            stream.Write(num1);
            stream.Write(_0C);
            stream.Write(_10);
            stream.Write(_18);
            stream.Write(_20);
            stream.Write(_28);
            stream.Write(_30);
            stream.Write(num2);
            stream.Write(_38);
            if (num2 != 3735928559L)
                return;
            stream.Write(_40);
            stream.Write(_48);
        }
    }
}