/**
 * @file Scram.cpp
 *
 * This module contains the implementation of the Sasl::Client::Scram class.
 *
 * © 2019 by Richard Walters
 */

#include <Base64/Base64.hpp>
#include <Hash/Hmac.hpp>
#include <Hash/Pbkdf2.hpp>
#include <Sasl/Client/Scram.hpp>
#include <sstream>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <StringExtensions/StringExtensions.hpp>
#include <SystemAbstractions/CryptoRandom.hpp>
#include <vector>

namespace {

    /**
     * This is the number of characters to generate for nonce values.
     * Why 24?  Because the examples in RFC 5802 use 24-character nonce
     * values and say absolutely nothing about the length in characters.
     */
    constexpr size_t NONCE_LENGTH = 24;

    /**
     * This is the dictionary of characters that are allowed in nonce values.
     */
    const std::vector< char > PRINTABLES = {
        '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', '-', '.', '/',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        ':', ';', '<', '=', '>', '?', '@',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '[', '\\', ']', '^', '_', '`',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '{', '|', '}', '~',
    };

    /**
     * This is used to keep track of what stage the authentication
     * between client an server is in.
     **/
    enum class Step {
        /**
         * In this step, the client provides the username and nonce,
         * without any initial server message expected.
         */
        ClientNonce,

        /**
         * In this step, the client provides the proof based on the
         * challege (nonce, salt, iterations) provided by the server.
         */
        ServerChallenge,

        /**
         * In this step, the client verifies the signature provided by the
         * server.
         */
        ServerSignature,

        /**
         * In this step, no further client or server messages are expected.
         */
        Done,
    };

    /**
     * Convert the given encoded UTF-8 string into the equivalent byte vector.
     *
     * @param[in] s
     *     This is the encoded UTF-8 string to convert.
     *
     * @return
     *     This is the byte vector equivalent of the given string.
     */
    std::vector< uint8_t > ByteVectorFromString(const std::string& s) {
        return std::vector< uint8_t >(
            s.begin(),
            s.end()
        );
    }

    /**
     * Convert the given byte vector into the equivalent UTF-8 string.
     *
     * @param[in] s
     *     This is the byte vector to convert.
     *
     * @return
     *     This is the UTF-8 string equivalent of the given byte vector.
     */
    std::string StringFromByteVector(const std::vector< uint8_t >& v) {
        return std::string(
            v.begin(),
            v.end()
        );
    }

    /**
     * Apply the SASLprep profile [RFC4013] of the "stringprep" algorithm
     * [RFC3454] to the given input, returning the result.
     *
     * @note
     *     This is a pretty deep requirement to meet, so for now we'll
     *     just keep everything ASCII and nobody gets hurt. :)
     *
     * @param[in] input
     *     This is the string to normalize.
     *
     * @return
     *     The normalized string is returned.
     */
    std::string Normalize(const std::string& input) {
        // TODO:  This works only for ASCII.  This will need to be
        // updated to handle anything else.
        return input;
    }

    /**
     * Generate and return a cryptographically strong random sequence
     * of ASCII characters not including comma.
     *
     * @return
     *     The generated nonce is returned.
     */
    std::string MakeNonce() {
        static SystemAbstractions::CryptoRandom rng;
        std::vector< uint8_t > randomBytes(NONCE_LENGTH);
        rng.Generate(randomBytes.data(), randomBytes.size());
        std::ostringstream builder;
        for (auto randomByte: randomBytes) {
            builder << PRINTABLES[randomByte % PRINTABLES.size()];
        }
        return builder.str();
    }

}

namespace Sasl {
namespace Client {

    /**
     * This contains the private properties of a Scram instance.
     */
    struct Scram::Impl {
        // Properties

        /**
         * This is a helper object used to generate and publish
         * diagnostic messages.
         */
        SystemAbstractions::DiagnosticsSender diagnosticsSender;

        /**
         * This is used to keep track of what stage the authentication
         * between client an server is in.
         */
        Step step = Step::ClientNonce;

        /**
         * This is the hash function to use in the SCRAM algorithm.
         */
        HashFunction hashFunction;

        /**
         * This is the size, in bits, of digests produced by the selected
         * hash function.
         */
        size_t digestSize;

        /**
         * This is the Hash-based Message Authentication Code (HMAC)
         * function, derived from the selected hash function, to use
         * in the SCRAM algorithm.
         */
        std::function<
            std::vector< uint8_t >(
                const std::vector< uint8_t >&,
                const std::vector< uint8_t >&
            )
        > hmac;

        /**
         * This is the name provided by the client that provides the
         * authentication identity.
         */
        std::string username;

        /**
         * This is the client's password, normalized by the SASLprep profile
         * [RFC4013] of the "stringprep" algorithm [RFC3454].
         */
        std::vector< uint8_t > normalizedPassword;

        /**
         * This is the Base64 encoding of the GS2 Header provided by the
         * client.
         */
        std::string encodedChannelBinding;

        /**
         * This is a cryptographically strong string of printable ASCII
         * characters (without any comma) included in the SCRAM algorithm to
         * further protect the client's credentials.  A new one is generated
         * every time the algorithm is employed.
         */
        std::string clientNonce;

        /**
         * This is the text of the first line sent by the client to the server.
         */
        std::string clientFirstMessage;

        /**
         * This is the part of the client's first message that doesn't include
         * the GS2 header.
         */
        std::string clientFirstMessageBare;

        /**
         * This is the digest that the client computes and expects the server
         * to provide in order to verify that the server and client have
         * the same idea of what the password is.
         */
        std::vector< uint8_t > serverSignature;

        /**
         * This flag indicates whether or not the mechanism has determined
         * that the authentication procedure was successful.
         */
        bool succeeded = false;

        /**
         * This flag indicates whether or not the mechanism has determined
         * that the server provided an unexpected or incorrect message
         * during the authentication procedure.
         */
        bool faulted = false;

        // Methods

        /**
         * This is the default constructor of the structure
         */
        Impl()
            : diagnosticsSender("Scram")
        {
        }
    };

    Scram::~Scram() noexcept = default;
    Scram::Scram(Scram&& other) noexcept = default;
    Scram& Scram::operator=(Scram&& other) noexcept = default;

    Scram::Scram()
        : impl_(new Impl)
    {
    }

    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate Scram::SubscribeToDiagnostics(
        SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
        size_t minLevel
    ) {
        return impl_->diagnosticsSender.SubscribeToDiagnostics(delegate, minLevel);
    }

    void Scram::SetHashFunction(
        HashFunction hashFunction,
        size_t blockSize,
        size_t digestSize
    ) {
        impl_->hashFunction = hashFunction;
        impl_->hmac = Hash::MakeHmacBytesToBytesFunction(
            hashFunction,
            blockSize
        );
        impl_->digestSize = digestSize;
    }

    void Scram::Reset() {
        impl_->succeeded = false;
        impl_->faulted = false;
    }

    void Scram::SetCredentials(
        const std::string& credentials,
        const std::string& authenticationIdentity,
        const std::string& authorizationIdentity
    ) {
        impl_->username = authenticationIdentity;
        impl_->normalizedPassword = ByteVectorFromString(
            Normalize(credentials)
        );
        impl_->clientNonce = MakeNonce();
        impl_->clientFirstMessageBare = (
            "n=" + authenticationIdentity
            + ",r=" + impl_->clientNonce
        );
        const std::string gs2Header = (
            "n," + authorizationIdentity
            + ","
        );
        impl_->clientFirstMessage = (
            gs2Header + impl_->clientFirstMessageBare
        );
        impl_->encodedChannelBinding = Base64::Encode(gs2Header);
    }

    std::string Scram::GetInitialResponse() {
        impl_->diagnosticsSender.SendDiagnosticInformationString(
            0,
            "C: AUTH SCRAM* " + impl_->clientFirstMessage
        );
        return impl_->clientFirstMessage;
    }

    std::string Scram::Proceed(const std::string& message) {
        if (impl_->faulted) {
            return "";
        }
        switch (impl_->step) {
            case Step::ClientNonce: {
                impl_->step = Step::ServerChallenge;
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    0,
                    "C: AUTH SCRAM* " + impl_->clientFirstMessage
                );
                return impl_->clientFirstMessage;
            } break;

            case Step::ServerChallenge: {
                const auto pieces = StringExtensions::Split(message, ',');
                size_t numIterations = 1;
                std::string serverNonce;
                std::vector< uint8_t > salt;
                for (const auto piece: pieces) {
                    if (piece.length() < 3) {
                        impl_->faulted = true;
                        return "";
                    }
                    if (piece[1] != '=') {
                        impl_->faulted = true;
                        return "";
                    }
                    const auto value = piece.substr(2);
                    switch (piece[0]) {
                        case 'r': {
                            serverNonce = value;
                            if (
                                serverNonce.substr(0, impl_->clientNonce.length())
                                != impl_->clientNonce
                            ) {
                                impl_->faulted = true;
                                return "";
                            }
                        } break;

                        case 's': {
                            salt = ByteVectorFromString(Base64::Decode(value));
                        } break;

                        case 'i': {
                            if (sscanf(value.c_str(), "%zu", &numIterations) != 1) {
                                impl_->faulted = true;
                                return "";
                            }
                        } break;

                        default: break;
                    }
                }
                impl_->step = Step::ServerSignature;
                const auto saltedPassword = Hash::Pbkdf2(
                    impl_->hmac,
                    impl_->digestSize,
                    impl_->normalizedPassword,
                    salt,
                    numIterations,
                    impl_->digestSize / 8
                );
                const auto clientKey = impl_->hmac(saltedPassword, ByteVectorFromString("Client Key"));
                const auto storedKey = impl_->hashFunction(clientKey);
                const auto clientFinalMessageWithoutProof = (
                    "c=" + impl_->encodedChannelBinding
                    + ",r=" + serverNonce
                );
                const auto authMessage = ByteVectorFromString(
                    impl_->clientFirstMessageBare + ','
                    + message + ','
                    + clientFinalMessageWithoutProof
                );
                const auto clientSignature = impl_->hmac(storedKey, authMessage);
                std::vector< uint8_t > clientProof(storedKey.size());
                for (size_t i = 0; i < clientProof.size(); ++i) {
                    clientProof[i] = clientKey[i] ^ clientSignature[i];
                }
                const auto serverKey = impl_->hmac(
                    saltedPassword,
                    ByteVectorFromString("Server Key")
                );
                impl_->serverSignature = impl_->hmac(
                    serverKey,
                    authMessage
                );
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    0,
                    "C: " + clientFinalMessageWithoutProof + ",p=*******"
                );
                return (
                    clientFinalMessageWithoutProof
                    + ",p=" + Base64::Encode(StringFromByteVector(clientProof))
                );
            } break;

            case Step::ServerSignature: {
                impl_->step = Step::Done;
                const auto expectedMessage = (
                    "v=" + Base64::Encode(impl_->serverSignature)
                );
                if (message == expectedMessage) {
                    impl_->succeeded = true;
                }
                return "";
            } break;

            default: {
                return "";
            } break;

        }
        return "";
    }

    bool Scram::Succeeded() {
        return impl_->succeeded;
    }

    bool Scram::Faulted() {
        return impl_->faulted;
    }

}
}
