#pragma once

/**
 * @file Mechanism.hpp
 *
 * This module declares the Sasl::Client::Mechanism interface.
 *
 * © 2019 by Richard Walters
 */

#include <functional>
#include <memory>
#include <string>
#include <SystemAbstractions/DiagnosticsSender.hpp>

namespace Sasl {
namespace Client {

    /**
     * This represents the common interface to all client side
     * [SASL](https://tools.ietf.org/html/rfc4422) mechanisms.
     */
    class Mechanism {
        // Methods
    public:
        /**
         * This method forms a new subscription to diagnostic
         * messages published by the class.
         *
         * @param[in] delegate
         *     This is the function to call to deliver messages
         *     to the subscriber.
         *
         * @param[in] minLevel
         *     This is the minimum level of message that this subscriber
         *     desires to receive.
         *
         * @return
         *     A function is returned which may be called
         *     to terminate the subscription.
         */
        virtual SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        ) = 0;

        /**
         * Set the identities and credentials to use in the authentication.
         *
         * @param[in] credentials
         *     This is the information specific to the mechanism that
         *     the client uses to authenticate (e.g. certificate, ticket,
         *     password, etc.)
         *
         * @param[in] authenticationIdentity
         *     This is the identity to to associate with the credentials
         *     in the authentication.
         *
         * @param[in] authorizationIdentity
         *     This is the identity to "act as" in the authentication.
         *     If empty, the client is requesting to act as the identity the
         *     server associates with the client's credentials.
         */
        virtual void SetCredentials(
            const std::string& credentials,
            const std::string& authenticationIdentity,
            const std::string& authorizationIdentity = ""
        ) = 0;

        /**
         * Return the initial response the client should send in the
         * authentication request.
         *
         * @return
         *     The initial response the client should send in the
         *     authentication request is returned.
         *
         * @retval ""
         *     This is returned if this mechanism does not
         *     send an initial response in the authentication request.
         */
        virtual std::string GetInitialResponse() = 0;

        /**
         * Provide the next message received from the server, and obtain
         * the next message to send to the server.
         *
         * @param[in] message
         *     This is the next line of text received from the server.
         *     Some protocols, such as SMTP, will encode this in Base64.
         *     This method expects it to be decoded first before calling
         *     the method.
         *
         * @return
         *     The next line of text to send to the server is returned.
         *     If empty, the authentication operation is complete.
         */
        virtual std::string Proceed(const std::string& message) = 0;

        /**
         * Return an indication of whether or not the mechanism has determined
         * that the authentication procedure has succeeded.
         *
         * @return
         *     An indication of whether or not the mechanism has determined
         *     that the authentication procedure has succeeded is returned.
         *     A false value does not necessarily mean the authentication
         *     failed; it simply means the mechanism does not know.
         */
        virtual bool Succeeded() = 0;

        /**
         * Return an indication of whether or not the mechanism has determined
         * that the server has given an unexpected response/challenge.
         *
         * @return
         *     An indication of whether or not the mechanism has determined
         *     that the server has given an unexpected response/challenge
         *     is returned.
         */
        virtual bool Faulted() = 0;
    };

}
}
