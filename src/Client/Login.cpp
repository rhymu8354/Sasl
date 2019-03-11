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
    };

    Login::~Login() noexcept = default;
    Login::Login(Login&& other) noexcept = default;
    Login& Login::operator=(Login&& other) noexcept = default;

    Login::Login()
        : impl_(new Impl)
    {
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
        return "";
    }

    std::string Login::Proceed(const std::string& message) {
        switch (++impl_->numChallenges) {
            case 1: return impl_->username;
            case 2: return impl_->password;
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
