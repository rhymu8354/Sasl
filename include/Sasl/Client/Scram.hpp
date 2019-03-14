#pragma once

/**
 * @file Scram.hpp
 *
 * This module declares the Sasl::Client::Scram class.
 *
 * © 2019 by Richard Walters
 */

#include "Mechanism.hpp"

#include <functional>
#include <memory>

namespace Sasl {
namespace Client {

    /**
     * This class implements the Salted Challenge Response Authentication
     * Mechanism (SCRAM) SASL ([RFC 5802](https://tools.ietf.org/html/rfc5802))
     * mechanism.
     */
    class Scram
        : public Mechanism
    {
        // Types
    public:
        /**
         * This is the type of function SCRAM needs to compute digests
         * as part of the algorithm.
         *
         * @param[in] input
         *     This is the sequence of octets for which to compute a digest.
         *
         * @return
         *     The digest, as a sequence of octets, is returned.
         */
        using HashFunction = std::function<
            std::vector< uint8_t >(
                const std::vector< uint8_t >& input
            )
        >;

        // Lifecycle management
    public:
        ~Scram() noexcept;
        Scram(const Scram&) = delete;
        Scram(Scram&&) noexcept;
        Scram& operator=(const Scram&) = delete;
        Scram& operator=(Scram&&) noexcept;

        // Public methods
    public:
        /**
         * This is the default constructor.
         */
        Scram();

        /**
         * Set up the given hash function to be used in the SCRAM algorithm.
         *
         * @param[in] hashFunction
         *     This is the hash function to use in the SCRAM algorithm.
         *
         * @param[in] blockSize
         *     This is the block size, in bytes, of the given hash function.
         *
         * @param[in] digestSize
         *     This is the size, in bits, of the digest produced by the given
         *     hash function.
         */
        void SetHashFunction(
            HashFunction hashFunction,
            size_t blockSize,
            size_t digestSize
        );

        // Mechanism
    public:
        virtual SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        ) override;
        virtual void SetCredentials(
            const std::string& credentials,
            const std::string& authenticationIdentity,
            const std::string& authorizationIdentity = ""
        ) override;
        virtual std::string GetInitialResponse() override;
        virtual std::string Proceed(const std::string& message) override;
        virtual bool Succeeded() override;
        virtual bool Faulted() override;

        // Private properties
    private:
        /**
         * This is the type of structure that contains the private
         * properties of the instance.  It is defined in the implementation
         * and declared here to ensure that it is scoped inside the class.
         */
        struct Impl;

        /**
         * This contains the private properties of the instance.
         */
        std::unique_ptr< Impl > impl_;
    };

}
}
