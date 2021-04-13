using System;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_FIND_CLOSE2 Response
    /// </summary>
    public class FindClose2Response : SMB1Command
    {
        public override SMB1Command Init()
        {
            base.Init();

            return this;
        }

        public FindClose2Response Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);

            return this;
        }

        public override CommandName CommandName => CommandName.SMB_COM_FIND_CLOSE2;
    }
}
