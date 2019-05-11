#pragma once

/**
 * @file Plain.hpp
 *
 * This module declares the Sasl::Client::Plain class.
 *
 * © 2019 by Richard Walters
 */

#include "Mechanism.hpp"

#include <functional>
#include <memory>

namespace Sasl {
namespace Client {

    /**
     * This class implements the Plain SASL
     * ([RFC 4616](https://tools.ietf.org/html/rfc4616))
     * mechanism.
     */
    class Plain
        : public Mechanism
    {
        // Lifecycle management
    public:
        ~Plain() noexcept;
        Plain(const Plain&) = delete;
        Plain(Plain&&) noexcept;
        Plain& operator=(const Plain&) = delete;
        Plain& operator=(Plain&&) noexcept;

        // Public methods
    public:
        /**
         * This is the default constructor.
         */
        Plain();

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
