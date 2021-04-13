/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using MemoryPools.Memory;
using MemoryPools.Collections.Specialized;
using SMBLibrary.Authentication.NTLM;
using Utilities;

namespace SMBLibrary.Authentication.GSSAPI
{
    public class GSSContext
    {
        internal IGSSMechanism Mechanism;
        internal object MechanismContext;

        internal GSSContext(IGSSMechanism mechanism, object mechanismContext)
        {
            Mechanism = mechanism;
            MechanismContext = mechanismContext;
        }
    }

    public class GSSProvider
    {
        public static readonly byte[] NTLMSSPIdentifier = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

        private List<IGSSMechanism> m_mechanisms;

        public GSSProvider(IGSSMechanism mechanism)
        {
            m_mechanisms = new List<IGSSMechanism>();
            m_mechanisms.Add(mechanism);
        }

        public GSSProvider(List<IGSSMechanism> mechanisms)
        {
            m_mechanisms = mechanisms;
        }

        public IMemoryOwner<byte> GetSPNEGOTokenInitBytes()
        {
            using var token = new SimpleProtectedNegotiationTokenInit();
            for (var index = 0; index < m_mechanisms.Count; index++)
            {
                var mechanism = m_mechanisms[index];
                token.MechanismTypeList.Add(Arrays.RentFrom<byte>(mechanism.Identifier));
            }

            return token.GetBytes(true);
        }

        public virtual NTStatus AcceptSecurityContext(ref GSSContext context, Span<byte> inputToken, out IMemoryOwner<byte> outputToken)
        {
            outputToken = null;
            SimpleProtectedNegotiationToken spnegoToken = null;
            try
            {
                spnegoToken = SimpleProtectedNegotiationToken.ReadToken(inputToken, 0, false);
            }
            catch
            {
            }

            try
            {

                if (spnegoToken != null)
                {
                    if (spnegoToken is SimpleProtectedNegotiationTokenInit)
                    {
                        var tokenInit = (SimpleProtectedNegotiationTokenInit) spnegoToken;
                        if (tokenInit.MechanismTypeList.Count == 0)
                        {
                            return NTStatus.SEC_E_INVALID_TOKEN;
                        }

                        // RFC 4178: Note that in order to avoid an extra round trip, the first context establishment token
                        // of the initiator's preferred mechanism SHOULD be embedded in the initial negotiation message.
                        var preferredMechanism = tokenInit.MechanismTypeList[0];
                        var mechanism = FindMechanism(preferredMechanism.Memory.Span);
                        var isPreferredMechanism = (mechanism != null);
                        if (!isPreferredMechanism)
                        {
                            mechanism = FindMechanism(ref tokenInit.MechanismTypeList);
                        }

                        if (mechanism != null)
                        {
                            NTStatus status;
                            context = new GSSContext(mechanism, null);
                            if (isPreferredMechanism)
                            {
                                IMemoryOwner<byte> mechanismOutput;
                                status = mechanism.AcceptSecurityContext(ref context.MechanismContext, tokenInit.MechanismToken.Memory.Span, out mechanismOutput);
                                outputToken = GetSPNEGOTokenResponseBytes(mechanismOutput.Memory.Span, status, mechanism.Identifier);
                                mechanismOutput.Dispose();
                            }
                            else
                            {
                                status = NTStatus.SEC_I_CONTINUE_NEEDED;
                                outputToken = GetSPNEGOTokenResponseBytes(null, status, mechanism.Identifier);
                            }

                            return status;
                        }

                        return NTStatus.SEC_E_SECPKG_NOT_FOUND;
                    }
                    else // SimpleProtectedNegotiationTokenResponse
                    {
                        if (context == null)
                        {
                            return NTStatus.SEC_E_INVALID_TOKEN;
                        }

                        var mechanism = context.Mechanism;
                        var tokenResponse = (SimpleProtectedNegotiationTokenResponse) spnegoToken;
                        IMemoryOwner<byte> mechanismOutput;
                        var status = mechanism.AcceptSecurityContext(ref context.MechanismContext, tokenResponse.ResponseToken.Memory.Span, out mechanismOutput);
                        outputToken = GetSPNEGOTokenResponseBytes(mechanismOutput.Memory.Span, status, null);
                        mechanismOutput.Dispose();
                        return status;
                    }
                }
                else
                {
                    // [MS-SMB] The Windows GSS implementation supports raw Kerberos / NTLM messages in the SecurityBlob.
                    // [MS-SMB2] Windows [..] will also accept raw Kerberos messages and implicit NTLM messages as part of GSS authentication.
                    if (AuthenticationMessageUtils.IsSignatureValid(inputToken))
                    {
                        var messageType = AuthenticationMessageUtils.GetMessageType(inputToken);
                        var ntlmAuthenticationProvider = FindMechanism(NTLMSSPIdentifier);
                        if (ntlmAuthenticationProvider != null)
                        {
                            if (messageType == MessageTypeName.Negotiate)
                            {
                                context = new GSSContext(ntlmAuthenticationProvider, null);
                            }

                            if (context == null)
                            {
                                return NTStatus.SEC_E_INVALID_TOKEN;
                            }

                            var status = ntlmAuthenticationProvider.AcceptSecurityContext(ref context.MechanismContext,
                                inputToken, out outputToken);
                            return status;
                        }
                        else
                        {
                            return NTStatus.SEC_E_SECPKG_NOT_FOUND;
                        }
                    }
                }
            }
            finally
            {
                spnegoToken?.Dispose();
            }
            return NTStatus.SEC_E_INVALID_TOKEN;
        }

        public virtual object GetContextAttribute(GSSContext context, GSSAttributeName attributeName)
        {
            if (context == null)
            {
                return null;
            }
            var mechanism = context.Mechanism;
            return mechanism.GetContextAttribute(context.MechanismContext, attributeName);
        }

        public virtual bool DeleteSecurityContext(ref GSSContext context)
        {
            if (context != null)
            {
                var mechanism = context.Mechanism;
                return mechanism.DeleteSecurityContext(ref context.MechanismContext);
            }
            return false;
        }

        /// <summary>
        /// Helper method for legacy implementation.
        /// </summary>
        public virtual NTStatus GetNTLMChallengeMessage(out GSSContext context, NegotiateMessage negotiateMessage, out ChallengeMessage challengeMessage)
        {
            var ntlmAuthenticationProvider = FindMechanism(NTLMSSPIdentifier);
            if (ntlmAuthenticationProvider != null)
            {
                context = new GSSContext(ntlmAuthenticationProvider, null);
                IMemoryOwner<byte> outputToken;
                var inputToken = negotiateMessage.GetBytes();
                var result = ntlmAuthenticationProvider.AcceptSecurityContext(ref context.MechanismContext, inputToken.Memory.Span, out outputToken);
                challengeMessage = new ChallengeMessage(outputToken.Memory.Span);
                inputToken.Dispose();
                outputToken.Dispose();
                return result;
            }

            context = null;
            challengeMessage = null;
            return NTStatus.SEC_E_SECPKG_NOT_FOUND;
        }

        /// <summary>
        /// Helper method for legacy implementation.
        /// </summary>
        public virtual NTStatus NTLMAuthenticate(GSSContext context, AuthenticateMessage authenticateMessage)
        {
            if (context != null && ByteUtils.AreByteArraysEqual(context.Mechanism.Identifier, NTLMSSPIdentifier))
            {
                var mechanism = context.Mechanism;
                IMemoryOwner<byte> outputToken;
                var inputToken = authenticateMessage.GetBytes();
                var result = mechanism.AcceptSecurityContext(ref context.MechanismContext, inputToken.Memory.Span, out outputToken);
                inputToken.Dispose();
                outputToken.Dispose();
                return result;
            }

            return NTStatus.SEC_E_SECPKG_NOT_FOUND;
        }

        public IGSSMechanism FindMechanism(ref LongLocalList<IMemoryOwner<byte>> mechanismIdentifiers)
        {
            for (var i = 0; i < mechanismIdentifiers.Count; i++)
            {
                var identifier = mechanismIdentifiers[i];
                var mechanism = FindMechanism(identifier.Memory.Span);
                if (mechanism != null)
                {
                    return mechanism;
                }
            }
            return null;
        }

        public IGSSMechanism FindMechanism(Span<byte> mechanismIdentifier)
        {
            for (var index = 0; index < m_mechanisms.Count; index++)
            {
                var mechanism = m_mechanisms[index];
                if (mechanism.Identifier.SequenceEqual(mechanismIdentifier))
                {
                    return mechanism;
                }
            }

            return null;
        }

        private static IMemoryOwner<byte> GetSPNEGOTokenResponseBytes(Span<byte> mechanismOutput, NTStatus status, Span<byte> mechanismIdentifier)
        {
            using var tokenResponse = new SimpleProtectedNegotiationTokenResponse();
            if (status == NTStatus.STATUS_SUCCESS)
            {
                tokenResponse.NegState = NegState.AcceptCompleted;
            }
            else if (status == NTStatus.SEC_I_CONTINUE_NEEDED)
            {
                tokenResponse.NegState = NegState.AcceptIncomplete;
            }
            else
            {
                tokenResponse.NegState = NegState.Reject;
            }
            tokenResponse.SupportedMechanism = Arrays.RentFrom<byte>(mechanismIdentifier);
            tokenResponse.ResponseToken = Arrays.RentFrom<byte>(mechanismOutput);
            return tokenResponse.GetBytes();
        }
    }
}
