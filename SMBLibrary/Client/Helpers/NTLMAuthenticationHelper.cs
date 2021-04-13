/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Security.Cryptography;
using MemoryPools.Memory;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;
using Utilities;

namespace SMBLibrary.Client
{
    public class NTLMAuthenticationHelper
    {
        private static byte[] sixteenBytesArray = new byte[16];

        public static IMemoryOwner<byte> GetNegotiateMessage(Span<byte> securityBlob, string domainName, AuthenticationMethod authenticationMethod)
        {
            var useGSSAPI = false;
            if (securityBlob.Length > 0)
            {
                SimpleProtectedNegotiationTokenInit inputToken = null;
                try
                {
                    inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, true) as SimpleProtectedNegotiationTokenInit;
                }
                catch
                {
                }

                try
                {
                    if (inputToken == null || !ContainsMechanism(inputToken))
                    {
                        return null;
                    }
                }
                finally
                {
                    inputToken?.Dispose();
                }
                useGSSAPI = true;
            }

            var negotiateMessage = new NegotiateMessage();
            negotiateMessage.NegotiateFlags = NegotiateFlags.UnicodeEncoding |
                                              NegotiateFlags.OEMEncoding |
                                              NegotiateFlags.Sign |
                                              NegotiateFlags.NTLMSessionSecurity |
                                              NegotiateFlags.DomainNameSupplied |
                                              NegotiateFlags.WorkstationNameSupplied |
                                              NegotiateFlags.AlwaysSign |
                                              NegotiateFlags.Version |
                                              NegotiateFlags.Use128BitEncryption |
                                              NegotiateFlags.KeyExchange |
                                              NegotiateFlags.Use56BitEncryption;

            if (authenticationMethod == AuthenticationMethod.NTLMv1)
            {
                negotiateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            }
            else
            {
                negotiateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
            }

            negotiateMessage.Version = NTLMVersion.Server2003;
            negotiateMessage.DomainName = domainName;
            negotiateMessage.Workstation = Environment.MachineName;
            if (useGSSAPI)
            {
                var outputToken = new SimpleProtectedNegotiationTokenInit();
                outputToken.MechanismTypeList.Add(Arrays.RentFrom<byte>(GSSProvider.NTLMSSPIdentifier));
                outputToken.MechanismToken = negotiateMessage.GetBytes();
                return outputToken.GetBytes(true);
            }

            return negotiateMessage.GetBytes();
        }

        public static IMemoryOwner<byte> GetAuthenticateMessage(Span<byte> securityBlob, string domainName, string userName, string password, AuthenticationMethod authenticationMethod, out byte[] sessionKey)
        {
            sessionKey = null;
            var useGSSAPI = false;
            SimpleProtectedNegotiationTokenResponse inputToken = null;
            try
            {
                inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, false) as SimpleProtectedNegotiationTokenResponse;
            }
            catch
            {
            }

            try
            {
                ChallengeMessage challengeMessage;
                if (inputToken != null)
                {
                    challengeMessage = GetChallengeMessage(inputToken.ResponseToken.Memory.Span);
                    useGSSAPI = true;
                }
                else
                {
                    challengeMessage = GetChallengeMessage(securityBlob);
                }

                if (challengeMessage == null)
                {
                    return null;
                }

                var time = DateTime.UtcNow;
                var clientChallenge = ExactArrayPool.Rent(8);
                StaticRandom.Instance.NextBytes(clientChallenge);

                var authenticateMessage = new AuthenticateMessage();
                // https://msdn.microsoft.com/en-us/library/cc236676.aspx
                authenticateMessage.NegotiateFlags = NegotiateFlags.Sign |
                                                     NegotiateFlags.NTLMSessionSecurity |
                                                     NegotiateFlags.AlwaysSign |
                                                     NegotiateFlags.Version |
                                                     NegotiateFlags.Use128BitEncryption |
                                                     NegotiateFlags.Use56BitEncryption;
                if ((challengeMessage.NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
                {
                    authenticateMessage.NegotiateFlags |= NegotiateFlags.UnicodeEncoding;
                }
                else
                {
                    authenticateMessage.NegotiateFlags |= NegotiateFlags.OEMEncoding;
                }

                if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
                {
                    authenticateMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;
                }

                if (authenticationMethod == AuthenticationMethod.NTLMv1)
                {
                    authenticateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
                }
                else
                {
                    authenticateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
                }

                authenticateMessage.UserName = userName;
                authenticateMessage.DomainName = domainName;
                authenticateMessage.WorkStation = Environment.MachineName;
                byte[] sessionBaseKey;
                byte[] keyExchangeKey;
                if (authenticationMethod == AuthenticationMethod.NTLMv1 ||
                    authenticationMethod == AuthenticationMethod.NTLMv1ExtendedSessionSecurity)
                {
                    if (authenticationMethod == AuthenticationMethod.NTLMv1)
                    {
                        // tochange:
                        authenticateMessage.LmChallengeResponse =
                            new SimpleMemoryOwner(NTLMCryptography.ComputeLMv1Response(challengeMessage.ServerChallenge, password), true).AsCountdown();
                        authenticateMessage.NtChallengeResponse =
                            new SimpleMemoryOwner(NTLMCryptography.ComputeNTLMv1Response(challengeMessage.ServerChallenge, password), true).AsCountdown();
                    }
                    else // NTLMv1ExtendedSessionSecurity
                    {
                        authenticateMessage.LmChallengeResponse =
                            new SimpleMemoryOwner(ByteUtils.Concatenate_Rental(clientChallenge, sixteenBytesArray), true).AsCountdown();
                        authenticateMessage.NtChallengeResponse =
                            new SimpleMemoryOwner(NTLMCryptography.ComputeNTLMv1ExtendedSessionSecurityResponse(challengeMessage.ServerChallenge, clientChallenge, password), true).AsCountdown();
                        
                    }

                    ExactArrayPool.Return(clientChallenge);

                    // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                    var ntowf = NTLMCryptography.NTOWFv1_Rental(password);
                    sessionBaseKey = Md4.GetByteHashFromBytes_Rental(ntowf);
                    ExactArrayPool.Return(ntowf);

                    var lmowf = NTLMCryptography.LMOWFv1(password);
                    keyExchangeKey = NTLMCryptography.KXKey_Rental(sessionBaseKey, authenticateMessage.NegotiateFlags,
                        authenticateMessage.LmChallengeResponse.Memory.Span, challengeMessage.ServerChallenge, lmowf);
                    ExactArrayPool.Return(sessionBaseKey);
                }
                else // NTLMv2
                {
                    using var clientChallengeStructure =
                        new NTLMv2ClientChallenge(time, clientChallenge, challengeMessage.TargetInfo);
                    
                    var clientChallengeStructurePadded = clientChallengeStructure.GetBytesPadded();
                    var ntProofStr = NTLMCryptography.ComputeNTLMv2Proof(challengeMessage.ServerChallenge,
                        clientChallengeStructurePadded, password, userName, domainName);

                    authenticateMessage.LmChallengeResponse = 
                        new SimpleMemoryOwner(NTLMCryptography.ComputeLMv2Response(
                            challengeMessage.ServerChallenge, clientChallenge, password, userName,
                            challengeMessage.TargetName), true).AsCountdown();
                    authenticateMessage.NtChallengeResponse =
                        new SimpleMemoryOwner(ByteUtils.Concatenate_Rental(ntProofStr, clientChallengeStructurePadded), true).AsCountdown();

                    // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                    var responseKeyNT = NTLMCryptography.NTOWFv2(password, userName, domainName);
                    sessionBaseKey = new HMACMD5(responseKeyNT).ComputeHash(ntProofStr);
                    keyExchangeKey = sessionBaseKey;
                    
                    ExactArrayPool.Return(clientChallengeStructurePadded);
                }

                authenticateMessage.Version = NTLMVersion.Server2003;

                // https://msdn.microsoft.com/en-us/library/cc236676.aspx
                if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
                {
                    sessionKey = ExactArrayPool.Rent(16);
                    StaticRandom.Instance.NextBytes(sessionKey);
                    authenticateMessage.EncryptedRandomSessionKey = new SimpleMemoryOwner(RC4.Encrypt(keyExchangeKey, sessionKey), true).AsCountdown();
                    ExactArrayPool.Return(sessionKey);
                }
                else
                {
                    sessionKey = keyExchangeKey;
                }

                if (useGSSAPI)
                {
                    using var outputToken = new SimpleProtectedNegotiationTokenResponse();
                    outputToken.ResponseToken = authenticateMessage.GetBytes();
                    authenticateMessage.Dispose();

                    return outputToken.GetBytes();
                }
                else
                {
                    var bytes = authenticateMessage.GetBytes();
                    authenticateMessage.Dispose();
                    return bytes;
                }
            }
            finally
            {
                inputToken?.Dispose();
            }
        }

        private static ChallengeMessage GetChallengeMessage(Span<byte> messageBytes)
        {
            if (AuthenticationMessageUtils.IsSignatureValid(messageBytes))
            {
                var messageType = AuthenticationMessageUtils.GetMessageType(messageBytes);
                if (messageType == MessageTypeName.Challenge)
                {
                    try
                    {
                        return new ChallengeMessage(messageBytes);
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
            return null;
        }

        private static bool ContainsMechanism(SimpleProtectedNegotiationTokenInit token)
        {
            for (var index = 0; index < token.MechanismTypeList.Count; index++)
            {
                if (token.MechanismTypeList[index].Memory.Span.SequenceEqual(GSSProvider.NTLMSSPIdentifier))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
