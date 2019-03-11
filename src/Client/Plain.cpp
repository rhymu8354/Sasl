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
        /**
         * This is the line to provide to the server to pass along
         * the credentials.
         */
        std::string encodedCredentials;

        /**
         * This indicates whether or not the credentials have been
         * sent to the server.
         */
        bool credentialsSent = false;
    };

    Plain::~Plain() noexcept = default;
    Plain::Plain(Plain&& other) noexcept = default;
    Plain& Plain::operator=(Plain&& other) noexcept = default;

    Plain::Plain()
        : impl_(new Impl)
    {
    }

    void Plain::SetCredentials(
        const std::string& credentials,
        const std::string& authenticationIdentity,
        const std::string& authorizationIdentity
    ) {
        std::ostringstream builder;
        builder << authorizationIdentity;
        builder << '\0';
        builder << authenticationIdentity;
        builder << '\0';
        builder << credentials;
        impl_->encodedCredentials = builder.str();
    }

    std::string Plain::GetInitialResponse() {
        return impl_->encodedCredentials;
    }

    std::string Plain::Proceed(const std::string& message) {
        if (impl_->credentialsSent) {
            return "";
        } else {
            impl_->credentialsSent = true;
            return impl_->encodedCredentials;
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
