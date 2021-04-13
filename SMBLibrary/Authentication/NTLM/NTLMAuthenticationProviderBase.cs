/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using SMBLibrary.Authentication.GSSAPI;

namespace SMBLibrary.Authentication.NTLM
{
    public abstract class NTLMAuthenticationProviderBase : IGSSMechanism
    {
        public static readonly byte[] NTLMSSPIdentifier = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

        public NTStatus AcceptSecurityContext(ref object context, Span<byte> inputToken, out IMemoryOwner<byte> outputToken)
        {
            outputToken = null;
            if (!AuthenticationMessageUtils.IsSignatureValid(inputToken))
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            var messageType = AuthenticationMessageUtils.GetMessageType(inputToken);
            if (messageType == MessageTypeName.Negotiate)
            {
                NegotiateMessage negotiateMessage;
                try
                {
                    negotiateMessage = new NegotiateMessage(inputToken);
                }
                catch
                {
                    return NTStatus.SEC_E_INVALID_TOKEN;
                }
                ChallengeMessage challengeMessage;
                var status = GetChallengeMessage(out context, negotiateMessage, out challengeMessage);
                outputToken = challengeMessage.GetBytes();
                return status;
            }

            if (messageType == MessageTypeName.Authenticate)
            {
                AuthenticateMessage authenticateMessage;
                try
                {
                    authenticateMessage = new AuthenticateMessage(inputToken);
                }
                catch
                {
                    return NTStatus.SEC_E_INVALID_TOKEN;
                }

                return Authenticate(context, authenticateMessage);
            }

            return NTStatus.SEC_E_INVALID_TOKEN;
        }

        public abstract NTStatus GetChallengeMessage(out object context, NegotiateMessage negotiateMessage, out ChallengeMessage challengeMessage);

        public abstract NTStatus Authenticate(object context, AuthenticateMessage authenticateMessage);

        public abstract bool DeleteSecurityContext(ref object context);

        public abstract object GetContextAttribute(object context, GSSAttributeName attributeName);

        public Span<byte> Identifier => NTLMSSPIdentifier;
    }
}
