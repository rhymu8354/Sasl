/**
 * @file PlainTests.cpp
 *
 * This module contains the unit tests of the
 * Sasl::Client::Plain class.
 *
 * © 2019 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Sasl/Client/Plain.hpp>

TEST(PlainTests, CredentialsInInitialResponse) {
    Sasl::Client::Plain mech;
    mech.SetCredentials("hunter2", "bob");
    const auto line = mech.GetInitialResponse();
    EXPECT_EQ(
        std::string("\0bob\0hunter2", 12),
        line
    );
}

TEST(PlainTests, CredentialsIncludingAuthorizationIdentity) {
    Sasl::Client::Plain mech;
    mech.SetCredentials("hunter2", "bob", "alex");
    const auto line = mech.GetInitialResponse();
    EXPECT_EQ(
        std::string("alex\0bob\0hunter2", 16),
        line
    );
}

TEST(PlainTests, CredentialsAfterEmptyServerMessage) {
    Sasl::Client::Plain mech;
    mech.SetCredentials("hunter2", "bob");
    const auto line = mech.Proceed("");
    EXPECT_EQ(
        std::string("\0bob\0hunter2", 12),
        line
    );
}

TEST(PlainTests, ProceedAfterCredentialsSent) {
    Sasl::Client::Plain mech;
    mech.SetCredentials("hunter2", "bob");
    (void)mech.Proceed("");
    const auto line = mech.Proceed("");
    EXPECT_EQ("", line);
}

TEST(PlainTests, MechanismCannotDetermineSuccess) {
    Sasl::Client::Plain mech;
    mech.SetCredentials("hunter2", "bob");
    EXPECT_FALSE(mech.Succeeded());
    (void)mech.Proceed("");
    EXPECT_FALSE(mech.Succeeded());
}
