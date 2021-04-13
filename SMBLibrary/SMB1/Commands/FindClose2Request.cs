using System;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_FIND_CLOSE2 Request
    /// </summary>
    public class FindClose2Request : SMB1Command
    {
        public const int ParameterCount = 2;
        // Parameters:
        public ushort SearchHandle;

        public override SMB1Command Init()
        {
            base.Init();

            return this;
        }

        public FindClose2Request Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            SearchHandle = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);

            return this;
        }

        public override CommandName CommandName => CommandName.SMB_COM_FIND_CLOSE2;
    }
}
