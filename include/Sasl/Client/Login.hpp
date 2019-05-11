#pragma once

/**
 * @file Login.hpp
 *
 * This module declares the Sasl::Client::Login class.
 *
 * © 2019 by Richard Walters
 */

#include "Mechanism.hpp"

#include <functional>
#include <memory>

namespace Sasl {
namespace Client {

    /**
     * This class implements the LOGIN SASL
     * ([draft-murchison-sasl-login](https://tools.ietf.org/html/draft-murchison-sasl-login-00))
     * mechanism.
     */
    class Login
        : public Mechanism
    {
        // Lifecycle management
    public:
        ~Login() noexcept;
        Login(const Login&) = delete;
        Login(Login&&) noexcept;
        Login& operator=(const Login&) = delete;
        Login& operator=(Login&&) noexcept;

        // Public methods
    public:
        /**
         * This is the default constructor.
         */
        Login();

        // Mechanism
    public:
        virtual SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        ) override;
        virtual void Reset() override;
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
