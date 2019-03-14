/**
 * @file Login.cpp
 *
 * This module contains the implementation of the Sasl::Client::Login class.
 *
 * © 2019 by Richard Walters
 */

#include <Sasl/Client/Login.hpp>
#include <stddef.h>

namespace Sasl {
namespace Client {

    /**
     * This contains the private properties of a Login instance.
     */
    struct Login::Impl {
        // Properties

        /**
         * This is a helper object used to generate and publish
         * diagnostic messages.
         */
        SystemAbstractions::DiagnosticsSender diagnosticsSender;

        /**
         * This is the text to provide the server after the first challenge.
         */
        std::string username;

        /**
         * This is the text to provide the server after the second challenge.
         */
        std::string password;

        /**
         * This counts the number of challenges the server has given.
         */
        size_t numChallenges = 0;

        // Methods

        /**
         * This is the default constructor of the structure
         */
        Impl()
            : diagnosticsSender("Login")
        {
        }
    };

    Login::~Login() noexcept = default;
    Login::Login(Login&& other) noexcept = default;
    Login& Login::operator=(Login&& other) noexcept = default;

    Login::Login()
        : impl_(new Impl)
    {
    }

    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate Login::SubscribeToDiagnostics(
        SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
        size_t minLevel
    ) {
        return impl_->diagnosticsSender.SubscribeToDiagnostics(delegate, minLevel);
    }

    void Login::SetCredentials(
        const std::string& credentials,
        const std::string& authenticationIdentity,
        const std::string& authorizationIdentity
    ) {
        impl_->username = authenticationIdentity;
        impl_->password = credentials;
    }

    std::string Login::GetInitialResponse() {
        impl_->diagnosticsSender.SendDiagnosticInformationString(
            0,
            "C: AUTH LOGIN"
        );
        return "";
    }

    std::string Login::Proceed(const std::string& message) {
        switch (++impl_->numChallenges) {
            case 1: {
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    0,
                    "C: " + impl_->username
                );
            } return impl_->username;

            case 2: {
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    0,
                    "C: *******"
                );
            } return impl_->password;

            default: return "";
        }
    }

    bool Login::Succeeded() {
        return false;
    }

    bool Login::Faulted() {
        return false;
    }

}
}
