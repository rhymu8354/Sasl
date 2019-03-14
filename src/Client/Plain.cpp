/**
 * @file Plain.cpp
 *
 * This module contains the implementation of the Sasl::Client::Plain class.
 *
 * © 2019 by Richard Walters
 */

#include <Sasl/Client/Plain.hpp>
#include <string>
#include <sstream>

namespace Sasl {
namespace Client {

    /**
     * This contains the private properties of a Plain instance.
     */
    struct Plain::Impl {
        // Properties

        /**
         * This is a helper object used to generate and publish
         * diagnostic messages.
         */
        SystemAbstractions::DiagnosticsSender diagnosticsSender;

        /**
         * This is the line to provide to the server to pass along
         * the credentials.
         */
        std::string encodedCredentialsToSend;

        /**
         * This is the line to publish to diagnostics when passing along
         * the credentials to the server.
         */
        std::string encodedCredentialsToPublishToDiagnostics;

        /**
         * This indicates whether or not the credentials have been
         * sent to the server.
         */
        bool credentialsSent = false;

        // Methods

        /**
         * This is the default constructor of the structure
         */
        Impl()
            : diagnosticsSender("Plain")
        {
        }
    };

    Plain::~Plain() noexcept = default;
    Plain::Plain(Plain&& other) noexcept = default;
    Plain& Plain::operator=(Plain&& other) noexcept = default;

    Plain::Plain()
        : impl_(new Impl)
    {
    }

    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate Plain::SubscribeToDiagnostics(
        SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
        size_t minLevel
    ) {
        return impl_->diagnosticsSender.SubscribeToDiagnostics(delegate, minLevel);
    }

    void Plain::SetCredentials(
        const std::string& credentials,
        const std::string& authenticationIdentity,
        const std::string& authorizationIdentity
    ) {
        std::ostringstream builderForSending, builderForDiagnostics;
        builderForSending     << authorizationIdentity;
        builderForDiagnostics << authorizationIdentity;
        builderForSending     << '\0';
        builderForDiagnostics << "\\0";
        builderForSending     << authenticationIdentity;
        builderForDiagnostics << authenticationIdentity;
        builderForSending     << '\0';
        builderForDiagnostics << "\\0";
        builderForSending     << credentials;
        builderForDiagnostics << "*******";
        impl_->encodedCredentialsToSend = builderForSending.str();
        impl_->encodedCredentialsToPublishToDiagnostics = builderForDiagnostics.str();
    }

    std::string Plain::GetInitialResponse() {
        impl_->diagnosticsSender.SendDiagnosticInformationString(
            0,
            "C: AUTH PLAIN " + impl_->encodedCredentialsToPublishToDiagnostics
        );
        return impl_->encodedCredentialsToSend;
    }

    std::string Plain::Proceed(const std::string& message) {
        if (impl_->credentialsSent) {
            return "";
        } else {
            impl_->credentialsSent = true;
            return impl_->encodedCredentialsToSend;
        }
    }

    bool Plain::Succeeded() {
        return false;
    }

    bool Plain::Faulted() {
        return false;
    }

}
}
