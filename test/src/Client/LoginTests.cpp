/**
 * @file LoginTests.cpp
 *
 * This module contains the unit tests of the
 * Sasl::Client::Login class.
 *
 * © 2019 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Sasl/Client/Login.hpp>

TEST(LoginTests, NoInitialResponse) {
    Sasl::Client::Login mech;
    mech.SetCredentials("hunter2", "bob");
    const auto line = mech.GetInitialResponse();
    EXPECT_EQ("", line);
}

TEST(LoginTests, ProvideUsernameAfterFirstChallenge) {
    Sasl::Client::Login mech;
    mech.SetCredentials("hunter2", "bob");
    const auto line = mech.Proceed("Username:");
    EXPECT_EQ("bob", line);
}

TEST(LoginTests, ProvidePasswordAfterSecondChallenge) {
    Sasl::Client::Login mech;
    mech.SetCredentials("hunter2", "bob");
    (void)mech.Proceed("Username:");
    const auto line = mech.Proceed("Password:");
    EXPECT_EQ("hunter2", line);
}

TEST(LoginTests, ProceedAfterSecondChallenge) {
    Sasl::Client::Login mech;
    mech.SetCredentials("hunter2", "bob");
    (void)mech.Proceed("Username:");
    (void)mech.Proceed("Password:");
    const auto line = mech.Proceed("");
    EXPECT_EQ("", line);
}

TEST(LoginTests, Reset) {
    Sasl::Client::Login mech;
    mech.SetCredentials("hunter2", "bob");
    (void)mech.Proceed("Username:");
    (void)mech.Proceed("Password:");
    mech.Reset();
    const auto line = mech.Proceed("Username:");
    EXPECT_EQ("bob", line);
}

TEST(LoginTests, MechanismCannotDetermineSuccess) {
    Sasl::Client::Login mech;
    mech.SetCredentials("hunter2", "bob");
    EXPECT_FALSE(mech.Succeeded());
    (void)mech.Proceed("Username:");
    EXPECT_FALSE(mech.Succeeded());
    (void)mech.Proceed("Password:");
    EXPECT_FALSE(mech.Succeeded());
}
