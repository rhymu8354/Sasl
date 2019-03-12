/**
 * @file ScramTests.cpp
 *
 * This module contains the unit tests of the
 * Sasl::Client::Scram class.
 *
 * © 2019 by Richard Walters
 */

#include <Base64/Base64.hpp>
#include <gtest/gtest.h>
#include <Hash/Hmac.hpp>
#include <Hash/Pbkdf2.hpp>
#include <Hash/Sha1.hpp>
#include <Sasl/Client/Scram.hpp>
#include <stdint.h>
#include <string>
#include <SystemAbstractions/StringExtensions.hpp>
#include <vector>

namespace {

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
     * This is used to return the results of
     * ComputeClientProofAndServerSignature.
     */
    struct ClientProofAndServerSignature {
        /**
         * This is the Base64 encoding of the proof the client computes
         * in order to authenticate.
         */
        std::string clientProof;

        /**
         * This is the Base64 encoding of the signature the server computes
         *
         */
        std::string serverSignature;
    };

    /**
     * Return the expected client proof for the SCRAM algorithm given
     * the required inputs.
     *
     * @param[in] username
     *     This is the authorization identity provided by the client.
     *
     * @param[in] password
     *     This is the client's password.
     *
     * @param[in] base64EncodedSalt
     *     This is the Base64 encoding of the salt to use in hashing the
     *     client's password.
     *
     * @param[in] clientNonce
     *     This is the nonce provided by the client.
     *
     * @param[in] serverNonce
     *     This is the nonce to use in hashing the client's password.
     *     It is the clientNonce with more random characters added at the
     *     end by the server.
     *
     * @param[in] numIterations
     *     This is the number of iterations to use in the algorithm.
     *
     * @param[in] hashFunction
     *     This is the hash function to use in the SCRAM algorithm.
     *
     * @param[in] blockSize
     *     This is the block size of the given hash function, in bytes.
     *
     * @param[in] digestSize
     *     This is the size, in bits, of the digest produced by the given
     *     hash function.
     *
     * @return
     *     The computed client proof and server signature are returned.
     */
    ClientProofAndServerSignature ComputeClientProofAndServerSignature(
        const std::string& username,
        const std::string& password,
        const std::string& base64EncodedSalt,
        const std::string& clientNonce,
        const std::string& serverNonce,
        size_t numIterations,
        std::function< std::vector< uint8_t >(const std::vector< uint8_t >&) > hashFunction,
        size_t blockSize,
        size_t digestSize
    ) {
        const auto salt = Base64::Decode(base64EncodedSalt);
        const auto hmac = Hash::MakeHmacBytesToBytesFunction(
            hashFunction,
            blockSize
        );
        const auto saltedPassword = Hash::Pbkdf2(
            hmac,
            digestSize,
            ByteVectorFromString(Normalize(password)),
            ByteVectorFromString(salt),
            numIterations,
            digestSize / 8
        );
        const auto clientKey = hmac(saltedPassword, ByteVectorFromString("Client Key"));
        const auto storedKey = hashFunction(clientKey);
        const std::string clientFirstMessageBare = (
            "n=" + username
            + ",r=" + clientNonce
        );
        const std::string clientFinalMessageWithoutProof = (
            "c=biws,r=" + serverNonce
        );
        const auto serverFirstMessage = SystemAbstractions::sprintf(
            "r=%s,s=%s,i=%zu",
            serverNonce.c_str(),
            base64EncodedSalt.c_str(),
            numIterations
        );
        const auto authMessage = ByteVectorFromString(
            clientFirstMessageBare + ','
            + serverFirstMessage + ','
            + clientFinalMessageWithoutProof
        );
        const auto clientSignature = hmac(storedKey, authMessage);
        std::vector< uint8_t > clientProof(storedKey.size());
        for (size_t i = 0; i < clientProof.size(); ++i) {
            clientProof[i] = clientKey[i] ^ clientSignature[i];
        }
        const auto serverKey = hmac(saltedPassword, ByteVectorFromString("Server Key"));
        const auto serverSignature = hmac(serverKey, authMessage);
        ClientProofAndServerSignature clientProofAndServerSignature;
        clientProofAndServerSignature.clientProof = Base64::Encode(
            StringFromByteVector(clientProof)
        );
        clientProofAndServerSignature.serverSignature = Base64::Encode(
            StringFromByteVector(serverSignature)
        );
        return clientProofAndServerSignature;
    }

}

TEST(ScramTests, ComputeClientProofAndServerSignature) {
    const std::string username = "user";
    const std::string password = "pencil";
    const std::string clientNonce = "fyko+d2lbbFgONRv9qkxdawL";
    const std::string serverNonce = clientNonce + "3rfcNHYJY1ZVvWVs7j";
    const std::string salt = "QSXCR+Q6sek8bf92";
    const size_t numIterations = 4096;
    const auto hashFunction = Hash::Sha1;
    const auto blockSize = Hash::SHA1_BLOCK_SIZE;
    const auto digestSize = 160;
    const std::string expectedClientProofEncoded = "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";
    const std::string expectedServerSignatureEncoded = "rmF9pqV8S7suAoZWja4dJRkFsKQ=";
    const auto actualClientProofAndServerSignature = ComputeClientProofAndServerSignature(
        username,
        password,
        salt,
        clientNonce,
        serverNonce,
        numIterations,
        hashFunction,
        blockSize,
        digestSize
    );
    EXPECT_EQ(expectedClientProofEncoded, actualClientProofAndServerSignature.clientProof);
    EXPECT_EQ(expectedServerSignatureEncoded, actualClientProofAndServerSignature.serverSignature);
}

TEST(ScramTests, CredentialsInInitialResponseNoAuthorizationIdentity) {
    Sasl::Client::Scram mech;
    mech.SetHashFunction(
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    mech.SetCredentials("hunter½", "bob");
    const auto line = mech.GetInitialResponse();
    ASSERT_GT(line.length(), 11);
    const auto clientNonce = line.substr(11);
    EXPECT_EQ(
        "n,,n=bob,r=",
        line.substr(0, 11)
    );
    EXPECT_FALSE(clientNonce.empty());
}

TEST(ScramTests, CredentialsIncludingAuthorizationIdentity) {
    Sasl::Client::Scram mech;
    mech.SetHashFunction(
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    mech.SetCredentials("hunter½", "bob", "alex");
    const auto line = mech.GetInitialResponse();
    ASSERT_GT(line.length(), 11);
    const auto clientNonce = line.substr(11);
    EXPECT_EQ(
        "n,alex,n=bob,r=",
        line.substr(0, 15)
    );
    EXPECT_FALSE(clientNonce.empty());
}

TEST(ScramTests, CredentialsAfterEmptyServerMessage) {
    Sasl::Client::Scram mech;
    mech.SetHashFunction(
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    mech.SetCredentials("hunter2", "bob");
    (void)mech.Proceed("");
    const auto line = mech.GetInitialResponse();
    const auto clientNonce = line.substr(11);
    EXPECT_EQ(
        "n,,n=bob,r=",
        line.substr(0, 11)
    );
    EXPECT_FALSE(clientNonce.empty());
}

TEST(ScramTests, ProceedAfterUserNameAndClientNonceSent) {
    Sasl::Client::Scram mech;
    mech.SetHashFunction(
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    mech.SetCredentials("hunter2", "bob");
    const auto usernameWithClientNonce = mech.Proceed("");
    const auto clientNonce = usernameWithClientNonce.substr(11);
    const auto serverNonce = clientNonce + "Poggers";
    const auto base64EncodedSalt = Base64::Encode("PJSalt");
    const auto line = mech.Proceed("r=" + serverNonce + ",s=" + base64EncodedSalt + ",i=4096");
    const auto expectedClientProofAndServerSignature = ComputeClientProofAndServerSignature(
        "bob",
        "hunter2",
        base64EncodedSalt,
        clientNonce,
        serverNonce,
        4096,
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    EXPECT_EQ("c=biws,r=" + serverNonce + ",p=" + expectedClientProofAndServerSignature.clientProof, line);
}

TEST(ScramTests, SuccessfulServerSignature) {
    Sasl::Client::Scram mech;
    mech.SetHashFunction(
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    mech.SetCredentials("hunter2", "bob");
    const auto usernameWithClientNonce = mech.Proceed("");
    const auto clientNonce = usernameWithClientNonce.substr(11);
    const auto serverNonce = clientNonce + "Poggers";
    const auto base64EncodedSalt = Base64::Encode("PJSalt");
    (void)mech.Proceed("r=" + serverNonce + ",s=" + base64EncodedSalt + ",i=4096");
    const auto expectedClientProofAndServerSignature = ComputeClientProofAndServerSignature(
        "bob",
        "hunter2",
        base64EncodedSalt,
        clientNonce,
        serverNonce,
        4096,
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    const auto line = mech.Proceed("v=" + expectedClientProofAndServerSignature.serverSignature);
    EXPECT_TRUE(mech.Succeeded());
}

TEST(ScramTests, UnsuccessfulServerSignature) {
    Sasl::Client::Scram mech;
    mech.SetHashFunction(
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    mech.SetCredentials("hunter2", "bob");
    const auto usernameWithClientNonce = mech.Proceed("");
    const auto clientNonce = usernameWithClientNonce.substr(11);
    const auto serverNonce = clientNonce + "Poggers";
    const auto base64EncodedSalt = Base64::Encode("PJSalt");
    (void)mech.Proceed("r=" + serverNonce + ",s=" + base64EncodedSalt + ",i=4096");
    const auto expectedClientProofAndServerSignature = ComputeClientProofAndServerSignature(
        "bob",
        "poggers",
        base64EncodedSalt,
        clientNonce,
        serverNonce,
        4096,
        Hash::Sha1,
        Hash::SHA1_BLOCK_SIZE,
        160
    );
    const auto line = mech.Proceed("v=" + expectedClientProofAndServerSignature.serverSignature);
    EXPECT_FALSE(mech.Succeeded());
}
